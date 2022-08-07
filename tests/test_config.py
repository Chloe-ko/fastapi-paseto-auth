import json
import pytest, os, pyseto
from pyseto import Key
from fastapi_paseto_auth import AuthPASETO
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from pydantic import BaseSettings, ValidationError
from typing import Sequence, Optional
from datetime import timedelta


@pytest.fixture(scope="function")
def client():
    app = FastAPI()

    @app.get("/protected")
    def protected(Authorize: AuthPASETO = Depends()):
        Authorize.paseto_required()

    client = TestClient(app)
    return client


def test_default_config():
    assert AuthPASETO._token is None
    assert AuthPASETO._token_location == {"headers"}
    assert AuthPASETO._current_user is None
    assert AuthPASETO._decoded_token is None
    assert AuthPASETO._secret_key is None
    assert AuthPASETO._public_key is None
    assert AuthPASETO._private_key is None
    assert AuthPASETO._purpose == "local"
    assert AuthPASETO._decode_leeway == 0
    assert AuthPASETO._encode_issuer is None
    assert AuthPASETO._decode_issuer is None
    assert AuthPASETO._decode_audience == ""
    assert AuthPASETO._denylist_enabled is False
    assert AuthPASETO._denylist_token_checks == {"access", "refresh"}
    assert AuthPASETO._token_in_denylist_callback is None
    assert AuthPASETO._header_name == "Authorization"
    assert AuthPASETO._header_type == "Bearer"

    assert AuthPASETO._access_token_expires.__class__ == timedelta
    assert int(AuthPASETO._access_token_expires.total_seconds()) == 900

    assert AuthPASETO._refresh_token_expires.__class__ == timedelta
    assert int(AuthPASETO._refresh_token_expires.total_seconds()) == 2592000


def test_token_expired_false(Authorize: AuthPASETO):
    class TokenFalse(BaseSettings):
        authpaseto_secret_key: str = "testing"
        authpaseto_access_token_expires: bool = False
        authpaseto_refresh_token_expires: bool = False

    @AuthPASETO.load_config
    def get_expired_false():
        return TokenFalse()

    key = Key.new(version=4, purpose="local", key=AuthPASETO._secret_key)

    access_token = Authorize.create_access_token(subject=1)
    assert "exp" not in pyseto.decode(key, access_token, deserializer=json).payload

    refresh_token = Authorize.create_refresh_token(subject=1)
    assert "exp" not in pyseto.decode(key, refresh_token, deserializer=json).payload


def test_secret_key_not_exist(client: TestClient, Authorize: AuthPASETO):
    AuthPASETO._secret_key = None

    with pytest.raises(RuntimeError, match=r"authpaseto_secret_key"):
        Authorize.create_access_token(subject="test")

    Authorize._secret_key = "secret"
    token = Authorize.create_access_token(subject=1)
    Authorize._secret_key = None

    with pytest.raises(RuntimeError, match=r"authpaseto_secret_key"):
        client.request(
            method="GET", url="/protected", headers={"Authorization": f"Bearer {token}"}
        )


def test_denylist_enabled_without_callback(client: TestClient):
    # set authpaseto_secret_key for create token
    class SettingsOne(BaseSettings):
        authpaseto_secret_key: str = "secret-key"
        # AuthPASETO denylist won't trigger if value not True
        authpaseto_denylist_enabled: bool = False

    @AuthPASETO.load_config
    def get_settings_one():
        return SettingsOne()

    Authorize = AuthPASETO()

    token = Authorize.create_access_token(subject="test")

    response = client.request(
        method="get", url="/protected", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    class SettingsTwo(BaseSettings):
        authpaseto_secret_key: str = "secret-key"
        authpaseto_denylist_enabled: bool = True
        authpaseto_denylist_token_checks: list = ["access"]

    @AuthPASETO.load_config
    def get_settings_two():
        return SettingsTwo()

    with pytest.raises(RuntimeError, match=r"@AuthPASETO.token_in_denylist_loader"):
        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )


def test_load_env_from_outside():
    DIR = os.path.abspath(os.path.dirname(__file__))
    private_txt = os.path.join(DIR, "private_key.pem")
    public_txt = os.path.join(DIR, "public_key.pem")

    with open(private_txt) as f:
        PRIVATE_KEY = f.read().strip()

    with open(public_txt) as f:
        PUBLIC_KEY = f.read().strip()

    # correct data
    class Settings(BaseSettings):
        authpaseto_token_location: list = ["headers"]
        authpaseto_secret_key: str = "testing"
        authpaseto_public_key: str = PUBLIC_KEY
        authpaseto_private_key: str = PRIVATE_KEY
        authpaseto_purpose: str = "local"
        authpaseto_version: int = 4
        authpaseto_decode_leeway: timedelta = timedelta(seconds=8)
        authpaseto_encode_issuer: str = "urn:foo"
        authpaseto_decode_issuer: str = "urn:foo"
        authpaseto_decode_audience: str = "urn:foo"
        authpaseto_denylist_token_checks: Sequence = ["refresh"]
        authpaseto_denylist_enabled: bool = False
        authpaseto_header_name: str = "Auth-Token"
        authpaseto_header_type: Optional[str] = None
        authpaseto_access_token_expires: timedelta = timedelta(minutes=2)
        authpaseto_refresh_token_expires: timedelta = timedelta(days=5)

    @AuthPASETO.load_config
    def get_valid_settings():
        return Settings()

    assert AuthPASETO._token_location == ["headers"]
    assert AuthPASETO._secret_key == "testing"
    assert AuthPASETO._public_key == PUBLIC_KEY
    assert AuthPASETO._private_key == PRIVATE_KEY
    assert AuthPASETO._purpose == "local"
    assert AuthPASETO._version == 4
    assert AuthPASETO._decode_leeway == timedelta(seconds=8)
    assert AuthPASETO._encode_issuer == "urn:foo"
    assert AuthPASETO._decode_issuer == "urn:foo"
    assert AuthPASETO._decode_audience == "urn:foo"
    assert AuthPASETO._denylist_token_checks == ["refresh"]
    assert AuthPASETO._denylist_enabled is False
    assert AuthPASETO._header_name == "Auth-Token"
    assert AuthPASETO._header_type is None
    assert AuthPASETO._access_token_expires == timedelta(minutes=2)
    assert AuthPASETO._refresh_token_expires == timedelta(days=5)

    with pytest.raises(TypeError, match=r"Config"):

        @AuthPASETO.load_config
        def invalid_data():
            return "test"

    with pytest.raises(ValidationError, match=r"authpaseto_token_location"):

        @AuthPASETO.load_config
        def get_invalid_token_location_type():
            return [("authpaseto_token_location", 1)]

    with pytest.raises(ValidationError, match=r"authpaseto_token_location"):

        @AuthPASETO.load_config
        def get_invalid_token_location_value():
            return [("authpaseto_token_location", {"header"})]

    with pytest.raises(ValidationError, match=r"authpaseto_secret_key"):

        @AuthPASETO.load_config
        def get_invalid_secret_key():
            return [("authpaseto_secret_key", 123)]

    with pytest.raises(ValidationError, match=r"authpaseto_public_key"):

        @AuthPASETO.load_config
        def get_invalid_public_key():
            return [("authpaseto_public_key", 123)]

    with pytest.raises(ValidationError, match=r"authpaseto_private_key"):

        @AuthPASETO.load_config
        def get_invalid_private_key():
            return [("authpaseto_private_key", 123)]

    with pytest.raises(ValidationError, match=r"authpaseto_purpose"):

        @AuthPASETO.load_config
        def get_invalid_purpose():
            return [("authpaseto_purpose", 123)]

    with pytest.raises(ValidationError, match=r"authpaseto_decode_leeway"):

        @AuthPASETO.load_config
        def get_invalid_decode_leeway():
            return [("authpaseto_decode_leeway", "test")]

    with pytest.raises(ValidationError, match=r"authpaseto_encode_issuer"):

        @AuthPASETO.load_config
        def get_invalid_encode_issuer():
            return [("authpaseto_encode_issuer", 1)]

    with pytest.raises(ValidationError, match=r"authpaseto_decode_issuer"):

        @AuthPASETO.load_config
        def get_invalid_decode_issuer():
            return [("authpaseto_decode_issuer", 1)]

    with pytest.raises(ValidationError, match=r"authpaseto_decode_audience"):

        @AuthPASETO.load_config
        def get_invalid_decode_audience():
            return [("authpaseto_decode_audience", 1)]

    with pytest.raises(ValidationError, match=r"authpaseto_denylist_enabled"):

        @AuthPASETO.load_config
        def get_invalid_denylist():
            return [("authpaseto_denylist_enabled", "test")]

    with pytest.raises(ValidationError, match=r"authpaseto_denylist_token_checks"):

        @AuthPASETO.load_config
        def get_invalid_denylist_token_checks():
            return [("authpaseto_denylist_token_checks", "string")]

    with pytest.raises(ValidationError, match=r"authpaseto_denylist_token_checks"):

        @AuthPASETO.load_config
        def get_invalid_denylist_str_token_check():
            return [("authpaseto_denylist_token_checks", ["access", "refreshh"])]

    with pytest.raises(ValidationError, match=r"authpaseto_header_name"):

        @AuthPASETO.load_config
        def get_invalid_header_name():
            return [("authpaseto_header_name", 1)]

    with pytest.raises(ValidationError, match=r"authpaseto_header_type"):

        @AuthPASETO.load_config
        def get_invalid_header_type():
            return [("authpaseto_header_type", 1)]

    with pytest.raises(ValidationError, match=r"authpaseto_access_token_expires"):

        @AuthPASETO.load_config
        def get_invalid_access_token():
            return [("authpaseto_access_token_expires", "lol")]

    with pytest.raises(ValidationError, match=r"authpaseto_access_token_expires"):

        @AuthPASETO.load_config
        def get_access_token_true_value():
            return [("authpaseto_access_token_expires", True)]

    with pytest.raises(ValidationError, match=r"authpaseto_refresh_token_expires"):

        @AuthPASETO.load_config
        def get_invalid_refresh_token():
            return [("authpaseto_refresh_token_expires", "lol")]

    with pytest.raises(ValidationError, match=r"authpaseto_refresh_token_expires"):

        @AuthPASETO.load_config
        def get_refresh_token_true_value():
            return [("authpaseto_refresh_token_expires", True)]
