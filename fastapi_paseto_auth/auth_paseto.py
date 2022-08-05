from datetime import datetime, timedelta
from typing import Optional, Dict, Sequence, Union, List
from fastapi import Request
from fastapi_paseto_auth.auth_config import AuthConfig
import uuid
import json
from pyseto import Key, Paseto, Token
from pyseto.exceptions import VerifyError, DecryptError
import pyseto
from fastapi_paseto_auth.exceptions import (
    InvalidHeaderError,
    InvalidPASETOPurposeError,
    PASETODecodeError,
    RevokedTokenError,
    MissingTokenError,
    AccessTokenRequired,
    RefreshTokenRequired,
    FreshTokenRequired,
    InvalidPASETOVersionError,
)


class AuthPASETO(AuthConfig):
    def __init__(self, req: Request = None) -> None:
        """
        Get PASETO header from incoming request and decode it
        """
        if req:
            if self.paseto_in_headers:
                auth_header = req.headers.get(self._header_name)
                if auth_header:
                    self._token = self._get_paseto_from_header(auth_header)

    def _get_paseto_from_header(self, auth_header: str) -> Optional[str]:
        """
        Get token from the headers
        :param auth_header: value from HeaderName
        """

        header_name, header_type = self._header_name, self._header_type

        parts: List[str] = auth_header.split()

        # Make sure the header is in a valid format that we are expecting
        if not header_type:
            # <HeaderName>: <PASETO>
            if len(parts) != 1:
                raise InvalidHeaderError(
                    status_code=422,
                    msg=f"Bad {header_name} header. Excepted value '<PASETO>'",
                )
            self._token = parts[0]
        else:
            # <HeaderName>: <HeaderType> <PASETO>
            if not parts[0].__contains__(header_type) or len(parts) != 2:
                raise InvalidHeaderError(
                    status_code=422,
                    msg=f"Bad {header_name} header. Expected value {header_type}.",
                )

            self._token = parts[1]

    def _get_paseto_identifier(self) -> str:
        return str(uuid.uuid4())

    def _get_secret_key(self, purpose: str, process: str) -> str:
        """
        Get secret key from fastapi config
        """

        if purpose not in ("local", "public"):
            raise ValueError("Algorithm must be local or public.")

        if purpose == "local":
            if not self._secret_key:
                raise RuntimeError(
                    f"authpaseto_secret_key must be set when using {purpose} purpose"
                )

            return self._secret_key

        if process == "encode":
            if not self._private_key:
                raise RuntimeError(
                    f"authpaseto_private_key must be set when using {purpose} purpose"
                )
            return self._private_key

        if process == "decode":
            if not self._public_key:
                raise RuntimeError(
                    f"authpaseto_public_key must be set when using {purpose} purpose"
                )
            return self._public_key

    def _get_int_from_datetime(self, value: datetime) -> int:
        """
        :param value: datetime with or without timezone, if don't contains timezone
                      it will managed as it is UTC
        :return: Seconds since the Epoch
        """
        if not isinstance(value, datetime):  # pragma: no cover
            raise TypeError("a datetime is required")
        return int(value.timestamp())

    def _create_token(
        self,
        subject: Union[str, int],
        type_token: str,
        exp_seconds: int,
        fresh: Optional[bool] = None,
        issuer: Optional[str] = None,
        purpose: Optional[str] = None,
        audience: Optional[Union[str, Sequence[str]]] = None,
        user_claims: Optional[Dict[str, Union[str, bool]]] = {},
        version: Optional[int] = None,
    ) -> str:
        """
        Create a token
        """
        if not isinstance(subject, (str, int)):
            raise TypeError("Subject must be a string or int")
        if not isinstance(fresh, bool):
            raise TypeError("Fresh must be a boolean")
        if audience and not isinstance(audience, (str, list, tuple, set, frozenset)):
            raise TypeError("audience must be a string or sequence")
        if purpose and not isinstance(purpose, str):
            raise TypeError("purpose must be a string")
        if version and not isinstance(version, int):
            raise TypeError("version must be an integer")
        if user_claims and not isinstance(user_claims, dict):
            raise TypeError("User claims must be a dictionary")

        reserved_claims = {
            "sub": subject,
            "nbf": self._get_int_from_datetime(datetime.utcnow()),
            "jti": self._get_paseto_identifier(),
        }

        custom_claims = {"type": type_token}

        if type_token == "access":
            custom_claims["fresh"] = fresh

        if issuer:
            custom_claims["iss"] = issuer

        purpose = purpose or self._purpose
        version = version or self._version

        if purpose not in ("local", "public"):
            raise ValueError("Purpose must be local or public.")

        secret_key = self._get_secret_key(purpose, "encode")

        paseto = Paseto.new(
            exp=exp_seconds,
            include_iat=True,
        )

        encoding_key = Key.new(version=version, purpose=purpose, key=secret_key)

        return paseto.encode(
            encoding_key,
            {**reserved_claims, **custom_claims, **user_claims},
            serializer=json,
        )

    def _has_token_in_denylist_callback(self) -> bool:
        """
        Return True if token denylist callback set
        """
        return self._token_in_denylist_callback is not None

    def _check_token_is_revoked(self) -> None:
        """
        Ensure that AUTHPASETO_DENYLIST_ENABLED is true and callback regulated, and then
        call function denylist callback with passing decode PASETO, if true
        raise exception Token has been revoked
        """
        if not self._denylist_enabled:
            return

        if not self._has_token_in_denylist_callback():
            raise RuntimeError(
                "A token_in_denylist_callback must be provided via "
                "the '@AuthPASETO.token_in_denylist_loader' if "
                "authpaseto_denylist_enabled is 'True'"
            )

        if self._token_in_denylist_callback.__func__(self._token):
            raise RevokedTokenError(status_code=401, message="Token has been revoked")

    def _get_expiry_seconds(
        self,
        type_token: str,
        expires_time: Optional[Union[timedelta, datetime, int, bool]] = None,
    ) -> Union[None, int]:
        if expires_time and not isinstance(
            expires_time, (timedelta, datetime, int, bool)
        ):
            raise TypeError("expires_time must be a timedelta, datetime, int or bool")

        if expires_time is not False:
            if type_token == "access":
                expires_time = expires_time or self._access_token_expires
            elif type_token == "refresh":
                expires_time = expires_time or self._refresh_token_expires

        if expires_time is False:
            if isinstance(expires_time, bool):
                if type_token == "access":
                    expires_time = self._access_token_expires
                elif type_token == "refresh":
                    expires_time = self._refresh_token_expires
            if isinstance(expires_time, timedelta):
                expires_time = int(expires_time.seconds)
            elif isinstance(expires_time, datetime):
                current_time = datetime.utcnow()
                valid_time: timedelta = expires_time - current_time
                expires_time = int(valid_time.seconds)

            return expires_time
        else:
            return None

    def create_access_token(
        self,
        subject: Union[str, int],
        fresh: Optional[bool] = False,
        purpose: Optional[str] = None,
        headers: Optional[Dict] = None,
        expires_time: Optional[Union[timedelta, datetime, int, bool]] = None,
        audience: Optional[Union[str, Sequence[str]]] = None,
        user_claims: Optional[Dict] = {},
    ) -> str:
        """
        Create a access token with 15 minutes for expired time (default),
        info for param and return check to function create token
        :return: hash token
        """
        return self._create_token(
            subject=subject,
            type_token="access",
            exp_time=self._get_expired_time("access", expires_time),
            fresh=fresh,
            purpose=purpose,
            headers=headers,
            audience=audience,
            user_claims=user_claims,
            issuer=self._encode_issuer,
        )

    def create_refresh_token(
        self,
        subject: Union[str, int],
        purpose: Optional[str] = None,
        headers: Optional[Dict] = None,
        expires_time: Optional[Union[timedelta, datetime, int, bool]] = None,
        audience: Optional[Union[str, Sequence[str]]] = None,
        user_claims: Optional[Dict] = {},
    ) -> str:
        """
        Create a refresh token with 30 days for expired time (default),
        info for param and return check to function create token
        :return: hash token
        """
        return self._create_token(
            subject=subject,
            type_token="refresh",
            exp_time=self._get_expired_time("refresh", expires_time),
            purpose=purpose,
            headers=headers,
            audience=audience,
            user_claims=user_claims,
        )

    def _get_token_version(
        self,
    ) -> int:
        parts = self._token.split(".")
        match parts[0]:
            case "v4":
                return 4
            case "v3":
                return 3
            case "v2":
                return 2
            case "v1":
                return 1
            case _:
                raise InvalidPASETOVersionError(
                    status_code=422, message=f"Invalid PASETO version {parts[0]}"
                )

    def _get_token_purpose(
        self,
    ) -> str:
        parts = self._token.split(".")
        match parts[1]:
            case "local":
                return "local"
            case "public":
                return "public"
            case _:
                raise InvalidPASETOPurposeError(
                    status_code=422, message=f"Invalid PASETO purpose {parts[1]}"
                )

    def _decode_token(self) -> Token:
        """
        Verified token and catch all error from paseto package and return decode token
        :param encoded_token: token hash
        :param issuer: expected issuer in the PASETO
        :return: raw data from the hash token in the form of a dictionary
        """

        purpose = self._get_token_purpose(self._token)
        version = self._get_token_version(self._token)

        secret_key = self._get_secret_key(purpose=purpose, process="decode")
        decoding_key = Key.new(version=version, purpose=purpose, key=secret_key)

        try:
            token = pyseto.decode(
                keys=decoding_key, token=self._token, deserializer=json
            )
            self._decoded_token = token
            self._current_user = token.payload["sub"]
            return token
        except Exception as err:
            raise PASETODecodeError(status_code=422, message=str(err))

    def get_token_payload(self) -> Optional[Dict[str, Union[str, int, bool]]]:
        """
        Get payload from token
        :param decoded_token: decoded token object
        :return: payload from token
        """

        if self._decode_token:
            return self._decoded_token.payload

        if not self._token:
            return None

        return self._decode_token(self._token).payload

    def get_jti(self) -> str:
        """
        Returns the JTI (unique identifier) of an encoded PASETO
        :param encoded_token: The encoded PASETO from parameter
        :return: string of JTI
        """
        return self.get_token_payload(self._token)["jti"]

    def get_paseto_subject(self) -> Optional[Union[str, int]]:
        """
        this will return the subject of the PASETO that is accessing this endpoint.
        If no PASETO is present, `None` is returned instead.
        :return: sub of PASETO
        """
        if not self._token:
            return None

        return self.get_token_payload(self._token)["sub"]

    def current_user(self) -> Optional[Union[str, int]]:
        """
        this will return the subject of the PASETO that is accessing this endpoint.
        If no PASETO was validated yet, returns none
        :return: sub of PASETO
        """

        return self._current_user

    def paseto_required(
        self,
        optional: bool = False,
        fresh: bool = False,
        refresh_token: bool = False,
    ) -> None:
        """
        This function will check whether the requester has a valid token. If not, it will raise an exception.
        :param optional: if True, the function will not raise an exception if no token is present
        :param fresh: if True, the function will raise an exception if the token is not fresh
        :param refresh_token: if True, the function will raise an exception if the token is not a refresh token
        :return: None
        """

        if not self._token:
            if not optional:
                raise MissingTokenError(
                    status_code=401, message="PASETO Authorization Token required"
                )
            else:
                return None

        try:
            self._decode_token()
        except (VerifyError, DecryptError) as err:
            if optional:
                return None
            else:
                raise err

        payload = self.get_token_payload()

        if not refresh_token and payload["type"] != "access":
            raise AccessTokenRequired(
                status_code=401,
                message=f"Access token required but {payload['type']} provided",
            )
        elif refresh_token and payload["type"] != "refresh":
            raise RefreshTokenRequired(
                status_code=401,
                message=f"Refresh token required but {payload['type']} provided",
            )

        if fresh:
            if not payload["fresh"]:
                raise FreshTokenRequired(
                    status_code=401, message="PASETO access token is not fresh"
                )
