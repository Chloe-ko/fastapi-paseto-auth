from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi_paseto_auth import AuthPASETO
from fastapi_paseto_auth.exceptions import AuthPASETOException
from routers import users, items
from pydantic import BaseModel

app = FastAPI()


class Settings(BaseModel):
    authpaseto_secret_key: str = "secret"


@AuthPASETO.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthPASETOException)
def authpaseto_exception_handler(request: Request, exc: AuthPASETOException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


app.include_router(users.router, tags=["users"])
app.include_router(items.router, tags=["items"])
