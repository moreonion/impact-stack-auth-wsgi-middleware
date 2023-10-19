"""Test the middleware by wrapping a Flask app that accepts JWT tokens."""

# pylint: disable=unused-argument

import datetime
import json

import fakeredis
import flask
import flask_jwt_extended
import pytest

from impact_stack.auth_wsgi_middleware import AuthMiddleware, from_config, init_app


@pytest.fixture(name="jwt", scope="class")
def fixture_jwt():
    """Create a Flask-JWT object."""
    return flask_jwt_extended.JWTManager()


@pytest.fixture(name="app", scope="class")
def fixture_app(jwt):
    """Get the test app for wrapping."""
    app = flask.Flask(__name__)
    app.debug = True
    app.config["SECRET_KEY"] = "super-secret"
    app.config["JWT_SECRET_KEY"] = "super-secret"
    app.config["JWT_HEADER_TYPE"] = "JWT"
    app.config["AUTH_REDIS_URL"] = "redis://localhost:6379/0"
    app.config["AUTH_REDIS_CLIENT_CLASS"] = fakeredis.FakeStrictRedis
    app.config["IMPACT_STACK_API_URL"] = "https://impact-stack.net/api"
    app.config["IMPACT_STACK_API_KEY"] = "api-key"
    # Provide a simple config_getter for tests. moflask.flask.BaseApp providers a better one.
    app.config_getter = app.config.get

    jwt.init_app(app)

    @flask_jwt_extended.jwt_required()
    def protected():
        data = flask_jwt_extended.get_jwt()
        return flask.jsonify(data)

    app.route("/protected")(protected)
    with app.app_context():
        yield app


@pytest.fixture(name="auth_middleware", scope="class")
def fixture_auth_middleware(app, jwt):
    """Initialize the auth middleware."""
    middleware = init_app(app)
    expire_in = datetime.timedelta(days=1)
    # pylint: disable=protected-access
    middleware.token_store._client.set(
        "user1-uuid",
        flask_jwt_extended.create_access_token("user1", expires_delta=expire_in),
        ex=expire_in,
    )
    return middleware


@pytest.fixture(name="client")
def fixture_client(app):
    """Define a test client instance and context."""
    return app.test_client()


@pytest.mark.usefixtures("auth_middleware")
class TestMiddleware:
    """Test the middleware."""

    def test_access_denied_without_cookie(self, client):
        """Test that a request without session ID gets a 401."""
        response = client.get("/protected")
        assert response.status_code == 401

    def test_access_denied_with_unsigned_cookie(self, client):
        """Test that a request with an unsigned session ID gets a 401."""
        client.set_cookie("session_uuid", "user1-uuid")
        response = client.get("/protected")
        assert response.status_code == 401

    def test_access_denied_with_invalid_signature(self, auth_middleware, client):
        """Test that a request with an invalid signature gets a 401."""
        invalid_uuid = "user1-uuid.invalid-signature"
        client.set_cookie(auth_middleware.cookie_handler.cookie_name, invalid_uuid)
        response = client.get("/protected")
        assert response.status_code == 401

    def test_get_current_identity(self, auth_middleware: AuthMiddleware, client, requests_mock):
        """Test that a request with a valid signed session ID gets a 200."""
        signed_uuid = auth_middleware.cookie_handler.signer.sign("user1-uuid").decode()
        cookie_name = auth_middleware.cookie_handler.cookie_name
        client.set_cookie(cookie_name, signed_uuid)
        response = client.get("/protected")
        assert response.status_code == 200
        data = json.loads(response.get_data(as_text=True))
        assert "sub" in data and data["sub"] == "user1"

        # Force a token refresh
        auth_middleware.token_refresher.minimum_life_time = (
            datetime.timedelta(days=1).total_seconds() + 1
        )
        # Due to https://github.com/jamielennox/requests-mock/issues/17 we have to generate the
        # Set-Cookie header here manually instead of using requests-mock to do it.
        headers = {"Set-Cookie": f"{cookie_name}={signed_uuid}; Max-Age=86400"}
        requests_mock.post("https://impact-stack.net/api/auth/v1/refresh", json={}, headers=headers)
        response = client.get("/protected")
        # The flask app response is returned.
        assert response.status_code == 200
        assert response.json["sub"] == "user1"
        # A new token is generated.
        assert len(requests_mock.request_history) == 1
        assert "Authorization" in requests_mock.request_history[0].headers
        # The cookie header is forwarded.
        assert "Set-Cookie" in response.headers
        assert response.headers["Set-Cookie"] == headers["Set-Cookie"]


def test_secret_key_precedence(app):
    """Test precedence of the secret key config variables."""
    del app.config["JWT_SECRET_KEY"]
    app.config["SECRET_KEY"] = "secret-key"
    assert from_config(app.config_getter).cookie_handler.signer.secret_keys == [b"secret-key"]
    app.config["JWT_SECRET_KEY"] = "jwt-secret-key"
    assert from_config(app.config_getter).cookie_handler.signer.secret_keys == [b"jwt-secret-key"]
    app.config["AUTH_SECRET_KEY"] = "auth-secret-key"
    assert from_config(app.config_getter).cookie_handler.signer.secret_keys == [b"auth-secret-key"]
