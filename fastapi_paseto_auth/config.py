from datetime import timedelta
from typing import Optional, Union, Sequence
from pydantic import BaseModel, validator, StrictBool, StrictInt, StrictStr


class LoadConfig(BaseModel):
    authpaseto_token_location: Optional[Sequence[StrictStr]] = {"headers"}
    authpaseto_secret_key: Optional[StrictStr] = None
    authpaseto_public_key: Optional[StrictStr] = None
    authpaseto_public_key_file: Optional[StrictStr] = None
    authpaseto_private_key: Optional[StrictStr] = None
    authpaseto_private_key_file: Optional[StrictStr] = None
    authpaseto_purpose: Optional[StrictStr] = "local"
    authpaseto_version: StrictInt = 4
    authpaseto_decode_leeway: Optional[Union[StrictInt, timedelta]] = 0
    authpaseto_encode_issuer: Optional[StrictStr] = None
    authpaseto_decode_issuer: Optional[StrictStr] = None
    authpaseto_decode_audience: Optional[Union[StrictStr, Sequence[StrictStr]]] = ""
    authpaseto_denylist_enabled: Optional[StrictBool] = False
    authpaseto_denylist_token_checks: Optional[Sequence[StrictStr]] = {
        "access",
        "refresh",
    }
    authpaseto_header_name: Optional[StrictStr] = "Authorization"
    authpaseto_header_type: Optional[StrictStr] = "Bearer"
    authpaseto_access_token_expires: Optional[
        Union[StrictBool, StrictInt, timedelta]
    ] = timedelta(minutes=15)
    authpaseto_refresh_token_expires: Optional[
        Union[StrictBool, StrictInt, timedelta]
    ] = timedelta(days=30)

    @validator("authpaseto_private_key")
    def validate_authpaseto_private_key(
        cls, v: Optional[StrictStr]
    ) -> Optional[StrictStr]:
        if v is None and cls.authpaseto_private_key_file is None:
            return None
        if v is None and cls.authpaseto_private_key_file is not None:
            with open(cls.authpaseto_private_key_file, "r") as f:
                v = f.read()
        if not isinstance(v, str):
            raise TypeError("authpaseto_private_key must be a string")
        return v

    @validator("authpaseto_public_key")
    def validate_authpaseto_public_key(
        cls, v: Optional[StrictStr]
    ) -> Optional[StrictStr]:
        if v is None and cls.authpaseto_public_key_file is None:
            return None
        if v is None and cls.authpaseto_public_key_file is not None:
            with open(cls.authpaseto_public_key_file, "r") as f:
                v = f.read()
        if not isinstance(v, str):
            raise TypeError("authpaseto_public_key must be a string")
        return v

    @validator("authpaseto_access_token_expires")
    def validate_access_token_expires(cls, v):
        if v is True:
            raise ValueError(
                "The 'authpaseto_access_token_expires' only accept value False (bool)"
            )
        return v

    @validator("authpaseto_refresh_token_expires")
    def validate_refresh_token_expires(cls, v):
        if v is True:
            raise ValueError(
                "The 'authpaseto_refresh_token_expires' only accept value False (bool)"
            )
        return v

    @validator("authpaseto_denylist_token_checks", each_item=True)
    def validate_denylist_token_checks(cls, v):
        if v not in ["access", "refresh"]:
            raise ValueError(
                "The 'authpaseto_denylist_token_checks' must be between 'access' or 'refresh'"
            )
        return v

    @validator("authpaseto_token_location", each_item=True)
    def validate_token_location(cls, v):
        if v not in ["headers"]:
            raise ValueError(
                "The 'authpaseto_token_location' must be between 'headers' or 'body'"
            )
        return v

    class Config:
        min_anystr_length = 1
        anystr_strip_whitespace = True
