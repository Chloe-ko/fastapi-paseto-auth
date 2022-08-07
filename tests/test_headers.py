import pytest
from fastapi_paseto_auth import AuthPASETO
from fastapi_paseto_auth.exceptions import AuthPASETOException
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from typing import Optional
from pydantic import BaseSettings


@pytest.fixture(scope="function")
def client():
    app = FastAPI()

    @app.exception_handler(AuthPASETOException)
    def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )

    @app.get("/protected")
    def protected(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return {"hello": "world"}

    client = TestClient(app)
    return client


def test_header_without_jwt(client):
    response = client.get("/protected", headers={"Authorization": "Bearer"})
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Bad Authorization header. Expected value 'Bearer <PASETO>'"
    }

    response = client.get("/protected", headers={"Authorization": "Bearer "})
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Bad Authorization header. Expected value 'Bearer <PASETO>'"
    }


def test_header_without_bearer(client):
    response = client.get("/protected", headers={"Authorization": "Test asd"})
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Bad Authorization header. Expected value 'Bearer <PASETO>'"
    }

    response = client.get("/protected", headers={"Authorization": "Test "})
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Bad Authorization header. Expected value 'Bearer <PASETO>'"
    }


def test_header_invalid_jwt(client):
    response = client.get("/protected", headers={"Authorization": "Bearer asd"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid PASETO format"}


def test_valid_header(client, Authorize):
    token = Authorize.create_access_token(subject="test")
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}
