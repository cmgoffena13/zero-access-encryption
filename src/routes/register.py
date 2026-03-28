from fastapi import APIRouter, HTTPException, Response, status
from sqlmodel import select

from src.database.models import User
from src.database.session import SessionDep
from src.routes.models.register import RegisterInput

register_router = APIRouter()


@register_router.post("/register")
async def register(
    input: RegisterInput,
    session: SessionDep,
    response: Response,
):
    user = User(username=input.username, salt=input.salt, verifier=input.verifier)
    user_id = (
        await session.exec(select(User.id).where(User.username == user.username))
    ).first()
    if user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists"
        )
    try:
        session.add(user)
        await session.commit()
        await session.refresh(user)
    except Exception as e:
        await session.rollback()
        raise e
    response.status_code = status.HTTP_201_CREATED
    return {"user_id": user.id}
