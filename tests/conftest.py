import pytest
from fastapi_paseto_auth import AuthPASETO


@pytest.fixture(scope="module")
def Authorize():
    return AuthPASETO()
