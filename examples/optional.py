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


@AuthPASETOException.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthPASETOException)
def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.post("/login")
def login(user: User, Authorize: AuthPASETO = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}


@app.get("/partially-protected")
def partially_protected(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required(optional=True)

    # If no paseto is sent in the request, get_subject() will return None
    current_user = Authorize.get_subject() or "anonymous"
    return {"user": current_user}
