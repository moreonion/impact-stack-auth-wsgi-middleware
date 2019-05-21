"""Main package for the auth wsgi middleware."""

import itsdangerous
import redis
from werkzeug.wrappers import BaseRequest


class AuthMiddleware:
    """WSGI middleware that turns session cookies into JWT tokens."""

    def __init__(self, app, token_store):
        """Wrap a flask app."""
        self.token_store = token_store
        self.wsgi_app = app.wsgi_app
        app.wsgi_app = self
        self.cookie_name = app.config.get('AUTH_COOKIE', 'session_uuid')
        secret_key = app.config.get('AUTH_SECRET_KEY', app.config.get('SECRET_KEY'))
        self.signer = itsdangerous.Signer(secret_key)

    def get_session_uuid(self, environ):
        """Read the session ID from the Cookie header and validate it."""
        request = BaseRequest(environ)
        data = request.cookies.get(self.cookie_name)
        if data:
            try:
                return self.signer.unsign(data).decode()
            except itsdangerous.exc.BadSignature:
                return None
        return None

    def __call__(self, environ, start_response):
        """Handle an incoming request."""
        token = self.token_store[self.get_session_uuid(environ)]
        if token:
            environ['HTTP_AUTHORIZATION'] = 'JWT ' + token.decode()
        return self.wsgi_app(environ, start_response)


class RedisStore:
    """Redis backend for the session store."""

    @classmethod
    def from_url(cls, url, client_class=redis.Redis):
        """Create a new instance by URL."""
        return cls(client_class.from_url(url))

    def __init__(self, client):
        """Create a new instance by passing a client instance."""
        self._client = client

    def __getitem__(self, name):
        """Read a value from the session store."""
        if name:
            return self._client.get(name)
        return None
