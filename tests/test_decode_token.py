import pytest, pyseto, time, os
from pyseto import Key
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

    @app.get("/protected")
    def protected(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return {"hello": "world"}

    @app.get("/raw_token")
    def raw_token(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return Authorize.get_token_payload()

    @app.get("/get_subject")
    def get_subject(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return Authorize.get_paseto_subject()

    @app.get("/get_jti")
    def get_subject(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return Authorize.get_jti()

    @app.get("/refresh_token")
    def get_refresh_token(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required(refresh_token=True)
        return Authorize.get_paseto_subject()

    client = TestClient(app)
    return client


@pytest.fixture(scope="function")
def default_access_token():
    return {
        "jti": "123",
        "sub": "test",
        "type": "access",
        "fresh": True,
    }


@pytest.fixture(scope="function")
def encoded_token(default_access_token):
    key = Key.new(4, "local", "secret-key")
    return pyseto.encode(key, default_access_token).decode("utf-8")


def test_verified_token(client: TestClient, encoded_token, Authorize: AuthPASETO):
    class SettingsOne(BaseSettings):
        AUTHPASETO_SECRET_KEY: str = "secret-key"
        AUTHPASETO_ACCESS_TOKEN_EXPIRES: int = 2

    @AuthPASETO.load_config
    def get_settings_one():
        return SettingsOne()

    # DecodeError
    response = client.get("/protected", headers={"Authorization": "Bearer test"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid PASETO format"}
    # InvalidSignatureError
    key = Key.new(4, "local", "secret")
    token = pyseto.encode(key, {"some": "payload"}).decode("utf-8")
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Failed to decrypt."}
    # ExpiredSignatureError
    token = Authorize.create_access_token(subject="test")
    time.sleep(3)
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Token expired."}

    class SettingsTwo(BaseSettings):
        AUTHPASETO_SECRET_KEY: str = "secret-key"
        AUTHPASETO_ACCESS_TOKEN_EXPIRES: int = 1
        AUTHPASETO_REFRESH_TOKEN_EXPIRES: int = 1
        AUTHPASETO_DECODE_LEEWAY: int = 2

    @AuthPASETO.load_config
    def get_settings_two():
        return SettingsTwo()

    access_token = Authorize.create_access_token(subject="test")
    refresh_token = Authorize.create_refresh_token(subject="test")
    time.sleep(2)
    # PASETO payload is now expired
    # But with some leeway, it will still validate
    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    response = client.get(
        "/refresh_token", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert response.status_code == 200
    assert response.json() == "test"

    # Valid Token
    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {encoded_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}


def test_get_raw_token(client, default_access_token, encoded_token):
    response = client.get(
        "/raw_token", headers={"Authorization": f"Bearer {encoded_token}"}
    )
    assert response.status_code == 200
    assert response.json() == default_access_token


def test_get_paseto_jti(
    client: TestClient, default_access_token, encoded_token, Authorize: AuthPASETO
):
    response = client.get(
        "/get_jti", headers={"Authorization": f"Bearer {encoded_token}"}
    )
    assert response.status_code == 200
    assert response.json() == default_access_token["jti"]


def test_get_paseto_subject(client, default_access_token, encoded_token):
    response = client.get(
        "/get_subject", headers={"Authorization": f"Bearer {encoded_token}"}
    )
    assert response.status_code == 200
    assert response.json() == default_access_token["sub"]


def test_invalid_paseto_issuer(client, Authorize):
    # No issuer claim expected or provided - OK
    token = Authorize.create_access_token(subject="test")
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    AuthPASETO._decode_issuer = "urn:foo"

    # Issuer claim expected and not provided - Not OK
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Token is missing the 'iss' claim"}

    AuthPASETO._decode_issuer = "urn:foo"
    AuthPASETO._encode_issuer = "urn:bar"

    # Issuer claim still expected and wrong one provided - not OK
    token = Authorize.create_access_token(subject="test")
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Token issuer is not valid"}

    AuthPASETO._decode_issuer = None
    AuthPASETO._encode_issuer = None


def test_valid_aud(client, Authorize):
    token_aud = ["foo", "bar"]
    AuthPASETO._decode_audience = ["foo", "bar"]

    access_token = Authorize.create_access_token(subject=1, audience=token_aud)
    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    refresh_token = Authorize.create_refresh_token(subject=1, audience=token_aud)
    response = client.get(
        "/refresh_token", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert response.status_code == 200
    assert response.json() == 1

    AuthPASETO._decode_audience = None


def test_invalid_aud_and_missing_aud(client, Authorize):
    token_aud = "bar"
    AuthPASETO._decode_audience = "foo"

    access_token = Authorize.create_access_token(subject=1, audience=token_aud)
    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "aud verification failed."}

    refresh_token = Authorize.create_refresh_token(subject=1)
    response = client.get(
        "/refresh_token", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "aud verification failed."}

    AuthPASETO._decode_audience = None
