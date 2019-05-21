"""Main package for the auth wsgi middleware."""

import itsdangerous
import redis
from werkzeug.wrappers import BaseRequest


class AuthMiddleware:
    """WSGI middleware that turns session cookies into JWT tokens."""

    @classmethod
    def init_app(cls, app):
        """Create a new middleware instance according to the app config and wrap the app."""
        cookie_name = app.config.get('AUTH_COOKIE', 'session_uuid')
        secret_key = app.config.get('AUTH_SECRET_KEY', app.config.get('SECRET_KEY'))
        signer = itsdangerous.Signer(secret_key)
        redis_url = app.config['AUTH_REDIS_URL']
        redis_client_class = app.config.get('AUTH_REDIS_CLIENT_CLASS', redis.Redis)
        store = RedisStore.from_url(redis_url, redis_client_class)

        return cls(signer, cookie_name, store).wrap(app)

    def wrap(self, app):
        """Wrap a Flask app."""
        self.wsgi_app = app.wsgi_app
        app.wsgi_app = self
        return self

    def __init__(self, signer, cookie_name, token_store):
        """Create a new instance."""
        self.signer = signer
        self.cookie_name = cookie_name
        self.token_store = token_store
        self.wsgi_app = None

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
