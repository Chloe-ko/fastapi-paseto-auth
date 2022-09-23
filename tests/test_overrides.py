from typing import Sequence
import pytest
from fastapi_paseto_auth import AuthPASETO
from fastapi_paseto_auth.exceptions import AuthPASETOException
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseSettings


@pytest.fixture(scope="function")
def client():
    app = FastAPI()

    class SettingsOne(BaseSettings):
        authpaseto_token_location: Sequence[str] = {"headers"}
        authpaseto_secret_key: str = "testing"

    @AuthPASETO.load_config
    def get_settings_one():
        return SettingsOne()

    @app.exception_handler(AuthPASETOException)
    def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )

    @app.get("/token_invalid_override")
    def protected_invalid_override(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required(token="token_override")

    @app.get("/token_override")
    def protected_override(Authorize: AuthPASETO = Depends()):
        test_token = Authorize.create_access_token(subject="test")
        Authorize.paseto_required(token=test_token)
        return {"hello": "world"}

    client = TestClient(app)
    return client


def test_invalid_override(client, Authorize):
    url = "/token_invalid_override"
    token = Authorize.create_access_token(subject="test")
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid PASETO format"}


def test_override(client):
    url = "/token_override"
    # if header not define return anonym user
    response = client.get(url)
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}
