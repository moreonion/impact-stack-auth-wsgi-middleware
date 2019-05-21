"""Main package for the auth wsgi middleware."""

import itsdangerous
from werkzeug.wrappers import BaseRequest


class AuthMiddleware:
    """WSGI middleware that turns session cookies into JWT tokens."""

    def __init__(self, app, token_store):
        """Wrap a flask app."""
        self.token_store = token_store
        self.wsgi_app = app.wsgi_app
        app.wsgi_app = self
        secret_key = app.config.get('AUTH_SECRET_KEY', app.config.get('SECRET_KEY'))
        self.signer = itsdangerous.Signer(secret_key)

    def get_session_uuid(self, environ):
        """Read the session ID from the Cookie header and validate it."""
        request = BaseRequest(environ)
        data = request.cookies.get('session_uuid')
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
            environ['HTTP_AUTHORIZATION'] = 'JWT ' + token
        return self.wsgi_app(environ, start_response)
