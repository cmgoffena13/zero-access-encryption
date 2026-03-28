from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select
from srp import Verifier

from src.database.models import User
from src.database.session import SessionDep
from src.routes.models.srp import (
    SRPChallengeInput,
    SRPChallengeOutput,
    SRPProofInput,
    SRPProofOutput,
)
from src.srp_session_store import SrpSessionStore, get_srp_session_store

srp_router = APIRouter()

SrpStoreDep = Annotated[SrpSessionStore, Depends(get_srp_session_store)]


@srp_router.post("/srp/challenge")
async def srp_challenge(
    input: SRPChallengeInput,
    session: SessionDep,
    srp_store: SrpStoreDep,
):
    result = await session.exec(select(User).where(User.username == input.username))
    user = result.first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    salt = user.salt
    verifier = user.verifier
    A = input.A
    svr = Verifier(input.username.encode(), salt, verifier, A)

    s, B = svr.get_challenge()
    if s is None or B is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    await srp_store.store(input.username, svr)

    output = SRPChallengeOutput(s=s, B=B)

    return output


@srp_router.post("/srp/verify")
async def srp_proof(
    input: SRPProofInput,
    session: SessionDep,
    srp_store: SrpStoreDep,
):
    username = input.username
    svr = await srp_store.pop(username)
    if svr is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    M_bytes = input.M

    HAMK_bytes = svr.verify_session(M_bytes)

    if HAMK_bytes is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    result = await session.exec(select(User).where(User.username == username))
    user = result.first()
    if user is None or user.id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    output = SRPProofOutput(
        HAMK=HAMK_bytes,
        user_id=user.id,
        salt=user.salt,
    )
    return output
