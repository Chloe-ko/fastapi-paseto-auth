from fastapi import APIRouter, Depends
from fastapi_paseto import AuthPASETO

router = APIRouter()


@router.get("/items")
def items(Authorize: AuthPASETO = Depends()):
    Authorize.paseto_required()

    items = ["item1", "item2", "item3"]

    return {"items": items}
