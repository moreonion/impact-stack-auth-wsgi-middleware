"""Test the middleware by wrapping a Flask app that accepts JWT tokens."""

# pylint: disable=redefined-outer-name

import json

import fakeredis
import flask_jwt_extended
import pytest
from flask import Flask, jsonify

from impact_stack.auth_wsgi_middleware import AuthMiddleware


@pytest.fixture(scope="class")
def jwt():
    """Create a Flask-JWT object."""
    return flask_jwt_extended.JWTManager()


@pytest.fixture(scope="class")
def app(jwt):
    """Get the test app for wrapping."""
    app = Flask(__name__)
    app.debug = True
    app.config["SECRET_KEY"] = "super-secret"
    app.config["JWT_SECRET_KEY"] = "super-secret"
    app.config["JWT_HEADER_TYPE"] = "JWT"
    app.config["AUTH_REDIS_URL"] = "redis://localhost:6379/0"
    app.config["AUTH_REDIS_CLIENT_CLASS"] = fakeredis.FakeStrictRedis

    jwt.init_app(app)

    @flask_jwt_extended.jwt_required()
    def protected():
        data = flask_jwt_extended.get_jwt()
        return jsonify(data)

    app.route("/protected")(protected)
    with app.app_context():
        yield app


@pytest.fixture(scope="class")
def auth_middleware(app, jwt):
    """Initialize the auth middleware."""
    # pylint: disable=protected-access,unused-argument
    m = AuthMiddleware.init_app(app)
    m.token_store._client.set("user1-uuid", flask_jwt_extended.create_access_token("user1"))
    return m


@pytest.fixture
def client(app):
    """Define a test client instance and context."""
    with app.test_client() as c:
        yield c


@pytest.mark.usefixtures("auth_middleware")
class TestMiddleware:
    """Test the middleware."""

    @staticmethod
    def test_access_denied_without_cookie(client):
        """Test that a request without session ID gets a 401."""
        response = client.get("/protected")
        assert response.status_code == 401

    @staticmethod
    def test_access_denied_with_unsigned_cookie(client):
        """Test that a request with an unsigned session ID gets a 401."""
        client.set_cookie("localhost", "session_uuid", "user1-uuid")
        response = client.get("/protected")
        assert response.status_code == 401

    @staticmethod
    def test_access_denied_with_invalid_signature(auth_middleware, client):
        """Test that a request with an invalid signature gets a 401."""
        invalid_uuid = "user1-uuid.invalid-signature"
        client.set_cookie("localhost", auth_middleware.cookie_name, invalid_uuid)
        response = client.get("/protected")
        assert response.status_code == 401

    @staticmethod
    def test_get_current_identity(auth_middleware, client):
        """Test that a request with a valid signed session ID gets a 200."""
        signed_uuid = auth_middleware.signer.sign("user1-uuid")
        client.set_cookie("localhost", auth_middleware.cookie_name, signed_uuid)
        response = client.get("/protected")
        assert response.status_code == 200
        data = json.loads(response.get_data(as_text=True))
        assert "sub" in data and data["sub"] == "user1"
