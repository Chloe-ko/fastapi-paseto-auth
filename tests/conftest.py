import pytest
from fastapi_paseto import AuthPASETO


@pytest.fixture(scope="module")
def Authorize():
    return AuthPASETO()
