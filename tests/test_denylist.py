import pytest
from fastapi_paseto_auth import AuthPASETO
from fastapi_paseto_auth.exceptions import AuthPASETOException
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

# setting for denylist token
denylist = set()


@pytest.fixture(scope="function")
def client():
    AuthPASETO._denylist_enabled = True

    @AuthPASETO.token_in_denylist_loader
    def check_if_token_in_denylist(decrypted_token):
        jti = decrypted_token["jti"]
        return jti in denylist

    app = FastAPI()

    @app.exception_handler(AuthPASETOException)
    def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )

    @app.get("/paseto-required")
    def jwt_required(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return {"hello": "world"}

    @app.get("/paseto-optional")
    def jwt_optional(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return {"hello": "world"}

    @app.get("/paseto-refresh-required")
    def jwt_refresh_required(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required(refresh_token=True)
        return {"hello": "world"}

    @app.get("/fresh-paseto-required")
    def fresh_jwt_required(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required(fresh=True)
        return {"hello": "world"}

    @app.get("/get-jti")
    def get_access_jti(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()
        return {"jti": Authorize.get_jti()}

    @app.get("/get-refresh-jti")
    def get_refresh_jti(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required(refresh_token=True)
        return {"jti": Authorize.get_jti()}

    client = TestClient(app)
    return client


@pytest.fixture(scope="module")
def access_token(Authorize):
    return Authorize.create_access_token(subject="test", fresh=True)


@pytest.fixture(scope="module")
def refresh_token(Authorize):
    return Authorize.create_refresh_token(subject="test")


@pytest.mark.parametrize(
    "url", ["/paseto-required", "/paseto-optional", "/fresh-paseto-required"]
)
def test_non_denylisted_access_token(client, url, access_token, Authorize: AuthPASETO):
    response = client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # revoke token in last test url
    if url == "/fresh-paseto-required":
        response = client.get(
            "/get-jti", headers={"Authorization": f"Bearer {access_token}"}
        )
        jti = response.json()["jti"]
        denylist.add(jti)


def test_non_denylisted_refresh_token(client, refresh_token, Authorize: AuthPASETO):
    url = "/paseto-refresh-required"
    response = client.get(url, headers={"Authorization": f"Bearer {refresh_token}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # revoke token
    response = client.get(
        "/get-refresh-jti", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    jti = response.json()["jti"]
    denylist.add(jti)


@pytest.mark.parametrize(
    "url", ["/paseto-required", "/paseto-optional", "/fresh-paseto-required"]
)
def test_denylisted_access_token(client, url, access_token):
    response = client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Token has been revoked"}


def test_denylisted_refresh_token(client, refresh_token):
    url = "/paseto-refresh-required"
    response = client.get(url, headers={"Authorization": f"Bearer {refresh_token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Token has been revoked"}
