"""Define test fixtures."""

import pytest
import requests_mock


@pytest.fixture(name="block_requests", autouse=True)
def fixture_block_requests():
    """Don’t allow any remote HTTP requests."""
    with requests_mock.Mocker() as mocker:
        yield mocker
