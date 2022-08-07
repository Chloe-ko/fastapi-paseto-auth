from fastapi import APIRouter, Depends, HTTPException
from fastapi_paseto_auth import AuthPASETO
from pydantic import BaseModel


class User(BaseModel):
    username: str
    password: str


router = APIRouter()


@router.post("/login")
def login(user: User, Authorize: AuthPASETO = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}
