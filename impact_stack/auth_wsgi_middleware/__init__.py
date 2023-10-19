"""Main package for the auth wsgi middleware."""

import functools
import hashlib
from typing import Optional

import itsdangerous
import redis
from werkzeug.wrappers import Request

from impact_stack import rest


class TokenRefresher:
    """Call the auth-app for a new token when needed."""

    # pylint: disable=too-few-public-methods

    def __init__(self, auth_client, minimum_life_time) -> None:
        """Create a new token refresher."""
        self.auth_client = auth_client
        self.minimum_life_time = minimum_life_time

    def __call__(self, ttl: int, environ) -> Optional[str]:
        """Refresh the token when needed."""
        if ttl >= self.minimum_life_time:
            return None
        response = self.auth_client.post(
            "refresh", headers={"Authorization": environ["HTTP_AUTHORIZATION"]}
        )
        return response.headers["set-cookie"]


class CookieHandler:
    """Utility to read and verify signed session uuids from the request."""

    # pylint: disable=too-few-public-methods

    def __init__(self, signer, cookie_name):
        """Create a new cookie handler."""
        self.signer = signer
        self.cookie_name = cookie_name

    def get_uuid(self, environ):
        """Read and verify the session uuid from the request environment."""
        request = Request(environ)
        data = request.cookies.get(self.cookie_name)
        if data:
            try:
                return self.signer.unsign(data).decode()
            except itsdangerous.exc.BadSignature:
                return None
        return None


class AuthMiddleware:
    """WSGI middleware that turns session cookies into JWT tokens."""

    def wrap(self, wsgi_app):
        """Wrap a Flask app."""
        self.wsgi_app = wsgi_app
        return self

    def __init__(self, cookie_handler, token_store, header_type, token_refresher):
        """Create a new instance."""
        self.cookie_handler = cookie_handler
        self.token_store = token_store
        self.wsgi_app = None
        self.header_type = header_type
        self.token_refresher = token_refresher

    def __call__(self, environ, start_response):
        """Handle an incoming request."""
        cookie = None
        if (uuid_ := self.cookie_handler.get_uuid(environ)) and (token := self.token_store[uuid_]):
            environ["HTTP_AUTHORIZATION"] = self.header_type + " " + token.decode()
            cookie = self.token_refresher(self.token_store.ttl(uuid_), environ)

        def _start_response(status, headers, exc_info=None):
            if cookie:
                headers.append(("Set-Cookie", cookie))
            return start_response(status, headers, exc_info)

        return self.wsgi_app(environ, _start_response)


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

    def ttl(self, name):
        """Get the remaining ttl in seconds for the session."""
        return self._client.ttl(name)


def from_config(config_getter):
    """Construct the middleware and all its dependencies."""
    auth_client = rest.ClientFactory.from_config(config_getter).get_client("auth")
    token_refresher = TokenRefresher(
        auth_client,
        config_getter("AUTH_MINIMUM_TOKEN_LIFE_TIME", 4 * 3600),
    )
    signer = itsdangerous.Signer(
        config_getter("AUTH_SECRET_KEY", None)
        or config_getter("JWT_SECRET_KEY", None)
        or config_getter("SECRET_KEY"),
        digest_method=config_getter("AUTH_SIGNATURE_ALGORITHM", hashlib.sha256),
    )
    cookie_handler = CookieHandler(
        signer,
        config_getter("AUTH_COOKIE", "session_uuid"),
    )
    token_store = RedisStore.from_url(
        config_getter("AUTH_REDIS_URL"),
        config_getter("AUTH_REDIS_CLIENT_CLASS", redis.Redis),
    )
    middleware = AuthMiddleware(
        cookie_handler,
        token_store,
        config_getter("JWT_HEADER_TYPE", "Bearer"),
        token_refresher,
    )
    return middleware


def init_app(app):
    """Configure the middleware using a flask-app and use it to wrap the wsgi_app."""
    middleware = from_config(app.config_getter)
    app.wsgi_app = middleware.wrap(app.wsgi_app)
    return middleware
