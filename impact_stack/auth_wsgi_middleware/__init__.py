"""Main package for the auth wsgi middleware."""

import hashlib
from typing import Optional

import itsdangerous
import redis
from werkzeug.wrappers import Request

from impact_stack import rest


class TokenRefresher:
    """Call the auth-app for a new token when needed."""

    @classmethod
    def from_app(cls, app):
        """Create a new token refresher using a Flask app."""
        return cls(
            auth_client=rest.ClientFactory.from_app(app).get_client("auth", needs_auth=False),
            minimum_life_time=app.config.get("AUTH_MINIMUM_TOKEN_LIFE_TIME", 4 * 3600),
        )

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


class AuthMiddleware:
    """WSGI middleware that turns session cookies into JWT tokens."""

    @classmethod
    def init_app(cls, app):
        """Create a new middleware instance according to the app config and wrap the app."""
        secret_key = app.config.get(
            "AUTH_SECRET_KEY", app.config.get("JWT_SECRET_KEY", app.config.get("SECRET_KEY"))
        )
        digest = app.config.get("AUTH_SIGNATURE_ALGORITHM", hashlib.sha256)

        redis_url = app.config["AUTH_REDIS_URL"]
        redis_client_class = app.config.get("AUTH_REDIS_CLIENT_CLASS", redis.Redis)

        return cls(
            signer=itsdangerous.Signer(secret_key, digest_method=digest),
            cookie_name=app.config.get("AUTH_COOKIE", "session_uuid"),
            token_store=RedisStore.from_url(redis_url, redis_client_class),
            header_type=app.config.get(
                "AUTH_HEADER_TYPE",
                app.config.get("JWT_HEADER_TYPE", "Bearer"),
            ),
            token_refresher=TokenRefresher.from_app(app),
        ).wrap(app)

    def wrap(self, app):
        """Wrap a Flask app."""
        self.wsgi_app = app.wsgi_app
        app.wsgi_app = self
        return self

    def __init__(self, signer, cookie_name, token_store, header_type, token_refresher):
        """Create a new instance."""
        # pylint: disable=too-many-arguments
        self.signer = signer
        self.cookie_name = cookie_name
        self.token_store = token_store
        self.wsgi_app = None
        self.header_type = header_type
        self.token_refresher = token_refresher

    def get_session_uuid(self, environ):
        """Read the session ID from the Cookie header and validate it."""
        request = Request(environ)
        data = request.cookies.get(self.cookie_name)
        if data:
            try:
                return self.signer.unsign(data).decode()
            except itsdangerous.exc.BadSignature:
                return None
        return None

    def __call__(self, environ, start_response):
        """Handle an incoming request."""
        cookie = None
        if (uuid_ := self.get_session_uuid(environ)) and (token := self.token_store[uuid_]):
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
