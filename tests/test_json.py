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

    @app.exception_handler(AuthPASETOException)
    def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )

    @app.get("/protected_json")
    def protected(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required(location="json")
        return {"hello": "world"}

    @app.get("/protected_json_refresh")
    def protected(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required(
            location="json", token_key="refresh_token", refresh_token=True
        )
        return {"hello": "world"}

    client = TestClient(app)
    return client


@pytest.fixture(scope="module")
def access_token(Authorize):
    return Authorize.create_access_token(subject="test", fresh=True)


@pytest.fixture(scope="module")
def refresh_token(Authorize):
    return Authorize.create_refresh_token(subject="test")


def test_invalid_json_token(client):
    # set authpaseto_secret_key for create token
    class SettingsOne(BaseSettings):
        authpaseto_secret_key: str = "testing"

    @AuthPASETO.load_config
    def get_settings_one():
        return SettingsOne()

    response = client.get("/protected_json", json={"access_token": "asd"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid PASETO format"}


def test_wrong_location(client, access_token):
    class SettingsOne(BaseSettings):
        authpaseto_token_location: Sequence[str] = {"headers"}
        authpaseto_secret_key: str = "testing"

    @AuthPASETO.load_config
    def get_settings_one():
        return SettingsOne()

    response = client.get(
        "/protected_json", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "PASETO Authorization Token required"}


def test_alternate_key(client, refresh_token):
    response = client.get(
        "/protected_json_refresh", json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}


def test_valid_json(client, access_token):
    # token = Authorize.create_access_token(subject="test")
    response = client.get("/protected_json", json={"access_token": access_token})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}
