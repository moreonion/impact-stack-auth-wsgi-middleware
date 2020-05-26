# WSGI authentication middleware

This app is just one piece in our bigger [authorization scheme for microservices](https://docs.google.com/document/d/1wbdSyAU0OV0e2rH-nh_IiJkgNDWyKXhptsJwIff64A0/edit?usp=sharing).
Its purpose is make migrating to session cookies simpler by ensuring that backend microservices only need to deal with JWTs that contain all the needed claims.

## Architecture decisions

* The session UUIDs are stored in a redis database that can be reached by the wrapped Flask app.
* The session UUIDs are passed as cookie values.
* The redis database contains a JWT for each valid session UUID. The middleware doesn’t care about the actual contents of the JWT it just needs to be there.
* The session UUIDs in the cookie are signed using `itsdangerous`. The middleware only handles session UUIDs with a valid signature.

## Usage

```python
from impact_stack.auth_wsgi_middleware import AuthMiddleware

app = Flask(__name__)
AuthMiddleware.init_app(app)
```

## Configuration variables

The middleware reads its configuration from the Flask `app.config` dictionary. All variables are prefixed with `AUTH_…`.

| variable                  | description                                                                                                                                                   |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AUTH_SECRET_KEY`         | The secret key used to verify the cookie value’s signature. It defaults to `SECRET_KEY`.                                                                      |
| `AUTH_SIGNATURE_ALGORITHM`| A hash function to use as digest method for signing the session IDs. Defaults to `hashlib.sha256`                                                             |
| `AUTH_COOKIE_NAME`        | Name of the cookie from which the the session UUID is read. Defaults to `session_uuid`.                                                                       |
| `AUTH_REDIS_URL`          | URL to a redis database (see the [redis-py documentation](https://redis-py.readthedocs.io/en/latest/#redis.Redis.from_url) for more information)).            |
| `AUTH_REDIS_CLIENT_CLASS` | The redis client class used by the middleware. Mostly needed for testing. Defaults to [`redis.Redis`](https://redis-py.readthedocs.io/en/latest/#redis.Redis) |
| `AUTH_HEADER_TYPE`         | Prefix used when adding the JWT to the HTTP Authorization header. Defaults to the value of `JWT_HEADER_TYPE` which in turn defaults to `'Bearer'`.           |
