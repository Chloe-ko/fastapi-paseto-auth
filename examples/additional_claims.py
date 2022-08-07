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

    # You can be passing custom claim to argument user_claims
    # in function create_access_token() or create_refresh_token()
    extra_claims = {"foo": ["fiz", "baz"]}
    access_token = Authorize.create_access_token(
        subject=user.username, user_claims=extra_claims
    )
    return {"access_token": access_token}


# In protected route, get the claims you added to the jwt with the
# get_token_payload() method
@app.get("/claims")
def user(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required()

    foo_claims = Authorize.get_token_payload()["foo"]
    return {"foo": foo_claims}
