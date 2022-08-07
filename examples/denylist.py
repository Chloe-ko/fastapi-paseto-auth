from typing import Dict
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_paseto_auth import AuthPASETO
from fastapi_paseto_auth.exceptions import AuthPASETOException
from pydantic import BaseModel

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


# set denylist enabled to True
# you can set to check access or refresh token or even both of them
class Settings(BaseModel):
    authpaseto_secret_key: str = "secret"
    authpaseto_denylist_enabled: bool = True
    authpaseto_denylist_token_checks: set = {"access", "refresh"}


@AuthPASETO.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthPASETOException)
def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


# A storage engine to save revoked tokens. in production,
# you can use Redis for storage system
denylist = set()

# For this example, we are just checking if the tokens jti
# (unique identifier) is in the denylist set. This could
# be made more complex, for example storing the blocked token in Redis
@AuthPASETO.token_in_denylist_loader
def check_if_token_in_denylist(token_payload: Dict):
    jti = token_payload["jti"]
    return jti in denylist


@app.post("/login")
def login(user: User, Authorize: AuthPASETO = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = Authorize.create_access_token(subject=user.username)
    refresh_token = Authorize.create_refresh_token(subject=user.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


# Standard refresh endpoint.
# A token whose identifier/jti was saved in the denylist will not
# be able to access this endpoint
@app.post("/refresh")
def refresh(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required(refresh_token=True)

    current_user = Authorize.get_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


# Endpoint for revoking the current users access token
@app.delete("/access-revoke")
def access_revoke(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required()

    jti = Authorize.get_token_payload()["jti"]
    denylist.add(jti)
    return {"detail": "Access token has been revoked"}


# Endpoint for revoking the current users refresh token
@app.delete("/refresh-revoke")
def refresh_revoke(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required(refresh_token=True)

    jti = Authorize.get_token_payload()["jti"]
    denylist.add(jti)
    return {"detail": "Refresh token has been revoke"}


# A token in denylist will not be able to access this any more
@app.get("/protected")
def protected(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required()

    current_user = Authorize.get_subject()
    return {"user": current_user}
