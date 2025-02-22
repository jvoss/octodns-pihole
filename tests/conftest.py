import pytest
from requests_mock import mock as requests_mock

MOCK_URL = 'http://pi-hole.mock'


@pytest.fixture
def mock_request():
    with requests_mock() as mock:
        mock.post(
            f"{MOCK_URL}/api/auth",
            status_code=200,
            headers={"sid": "Op+J4qepBOs6PuM0YDOoxg="},
            json={
                "session": {
                    "valid": True,
                    "totp": False,
                    "sid": "Op+J4qepBOs6PuM0YDOoxg=",
                    "csrf": "o0L+GeqnuMXJUbwmHKBNPw=",
                    "validity": 1800,
                    "message": "password incorrect",
                },
                "took": 0.03569769859313965,
            },
        )

        yield mock
