"""Python package metadata for installing the auth-wsgi-middleware as a dependency."""

from setuptools import setup

setup(
    name="impact-stack-auth-wsgi-middleware",
    version="0.0.1",
    packages=["impact_stack.auth_wsgi_middleware"],
    url="https://gitlab.more-onion.com/impact-stack/auth-wsgi-middleware",
    maintainer="Roman Zimmermann",
    maintainer_email="roman@more-onion.com",
    install_requires=[
        "itsdangerous",
        "redis",
        "werkzeug",
    ],
    python_requires="~=3.3",
)
