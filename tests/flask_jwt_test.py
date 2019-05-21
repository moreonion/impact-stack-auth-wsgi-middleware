"""Test the middleware by wrapping a Flask app that accepts JWT tokens."""

# pylint: disable=redefined-outer-name

import json
from collections import defaultdict
from unittest.mock import Mock

import pytest
from flask import Flask, jsonify
from flask_jwt import (
    JWT, _default_jwt_payload_handler, current_identity, jwt_required
)

from impact_stack.auth_wsgi_middleware import AuthMiddleware


@pytest.fixture(scope='class')
def jwt():
    """Create a Flask-JWT object."""
    jwt = JWT(identity_handler=lambda p: p)

    def payload_handler(identity):
        user = Mock()
        user.id = identity
        payload = _default_jwt_payload_handler(user)
        return payload

    jwt.jwt_payload_handler(payload_handler)
    return jwt


@pytest.fixture(scope='class')
def app(jwt):
    """Get the test app for wrapping."""
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['JWT_AUTH_URL_RULE'] = None

    jwt.init_app(app)

    @jwt_required()
    def protected():
        data = {}
        data.update(current_identity)
        return jsonify(data)

    app.route('/protected')(protected)
    with app.app_context():
        yield app


@pytest.fixture(scope='class')
def auth_middleware(app, jwt):
    """Initialize the auth middleware."""
    store = defaultdict(lambda: None)
    store['user1-uuid'] = jwt.jwt_encode_callback('user1').decode()
    return AuthMiddleware(app, store)


@pytest.fixture
def client(app):
    """Define a test client instance and context."""
    with app.test_client() as c:
        yield c


class TestMiddleware:
    """Test the middleware."""

    @staticmethod
    def test_access_denied_without_cookie(client):
        """Test that a request without session ID gets a 401."""
        response = client.get('/protected')
        assert response.status_code == 401

    @staticmethod
    def test_access_denied_with_unsigned_cookie(client):
        """Test that a request with an unsigned session ID gets a 401."""
        client.set_cookie('localhost', 'session_uuid', 'user1-uuid')
        response = client.get('/protected')
        assert response.status_code == 401

    @staticmethod
    def test_get_current_identity(auth_middleware, client):
        """Test that a request with a valid signed session ID gets a 200."""
        signed_uuid = auth_middleware.signer.sign('user1-uuid')
        client.set_cookie('localhost', 'session_uuid', signed_uuid)
        response = client.get('/protected')
        assert response.status_code == 200
        data = json.loads(response.get_data(as_text=True))
        del data['exp']
        del data['iat']
        del data['nbf']
        assert data == {
            'identity': 'user1',
        }
