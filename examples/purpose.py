from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_paseto_auth import AuthPASETO
from fastapi_paseto_auth.exceptions import AuthPASETOException
from pydantic import BaseModel

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


class Settings(BaseModel):
    authpaseto_secret_key: str = "secret"

    # Private and public keys are required if you want to use public purpose authentication
    authpaseto_private_key: str = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL7pfyWYtZD7fDPDm+W0kWbNo/AdbRrDjjxMOgy2EL1N
-----END PRIVATE KEY-----
"""
    authpaset_public_key: str = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAc4ZDHPLZ6eGU3yL4ApPpQUq4cQUA900NY1csJIcwAxY=
-----END PUBLIC KEY-----
"""


@AuthPASETO.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthPASETOException)
def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.post("/login")
def login(user: User, Authorize: AuthPASETO = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # You can define different purpose when creating a token
    access_token = Authorize.create_access_token(subject=user.username, purpose="local")
    refresh_token = Authorize.create_refresh_token(
        subject=user.username, purpose="public"
    )
    return {"access_token": access_token, "refresh_token": refresh_token}


# In a protected route, you don't need to worry about what type of key you are receiving
# because it will automatically be detected by the library.
@app.post("/refresh")
def refresh(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required(refresh_token=True)

    current_user = Authorize.get_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


@app.get("/protected")
def protected(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required()

    current_user = Authorize.get_subject()
    return {"user": current_user}
