"""FastAPI dependencies for authenticated routes."""

from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, status

from src.auth_tokens import user_id_from_token


def bearer_token(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    return authorization.removeprefix("Bearer ").strip()


def get_authenticated_user_id(token: Annotated[str, Depends(bearer_token)]) -> int:
    try:
        return user_id_from_token(token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        ) from None
