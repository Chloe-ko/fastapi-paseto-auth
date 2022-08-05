import pytest
from fastapi_paseto_auth import AuthJWT


@pytest.fixture(scope="module")
def Authorize():
    return AuthJWT()
