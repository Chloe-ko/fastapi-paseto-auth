from fastapi_paseto_auth.config import LoadConfig
from pydantic import ValidationError
from typing import Callable, List, Optional, Dict
from datetime import timedelta
from pyseto import Token


class AuthConfig:
    _token = None
    _token_parts = []
    _token_location = {"headers"}
    _current_user = None
    _decoded_token: Optional[Token] = None

    _secret_key = None
    _public_key = None
    _private_key = None
    _purpose = "local"
    _version = 4
    _decode_leeway = 0
    _encode_issuer = None
    _decode_issuer = None
    _decode_audience = ""
    _denylist_enabled = False
    _denylist_token_checks = {"access", "refresh"}
    _header_name = "Authorization"
    _header_type = "Bearer"
    _token_in_denylist_callback = None
    _access_token_expires = timedelta(minutes=15)
    _refresh_token_expires = timedelta(days=30)

    @property
    def paseto_in_headers(self) -> bool:
        return "headers" in self._token_location

    @classmethod
    def load_config(cls, settings: Callable[..., List[tuple]]) -> "AuthConfig":
        try:
            config = LoadConfig(**{key.lower(): value for key, value in settings()})

            cls._token_location = config.authpaseto_token_location
            cls._secret_key = config.authpaseto_secret_key
            cls._public_key = config.authpaseto_public_key
            cls._private_key = config.authpaseto_private_key
            cls._purpose = config.authpaseto_purpose
            cls._version = config.authpaseto_version
            cls._decode_leeway = config.authpaseto_decode_leeway
            cls._encode_issuer = config.authpaseto_encode_issuer
            cls._decode_issuer = config.authpaseto_decode_issuer
            cls._decode_audience = config.authpaseto_decode_audience
            cls._denylist_enabled = config.authpaseto_denylist_enabled
            cls._denylist_token_checks = config.authpaseto_denylist_token_checks
            cls._header_name = config.authpaseto_header_name
            cls._header_type = config.authpaseto_header_type
            cls._access_token_expires = config.authpaseto_access_token_expires
            cls._refresh_token_expires = config.authpaseto_refresh_token_expires
        except ValidationError:
            raise
        except Exception:
            raise TypeError("Config must be pydantic 'BaseSettings' or list of tuple")

    @classmethod
    def token_in_denylist_loader(cls, callback: Callable[..., bool]) -> "AuthConfig":
        """
        This decorator sets the callback function that will be called when
        a protected endpoint is accessed and will check if the JWT has been
        been revoked. By default, this callback is not used.

        *HINT*: The callback must be a function that takes decrypted_token argument,
        args for object AuthJWT and this is not used, decrypted_token is decode
        JWT (python dictionary) and returns *`True`* if the token has been deny,
        or *`False`* otherwise.
        """
        cls._token_in_denylist_callback = callback
