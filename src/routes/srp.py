import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select
from srp import Verifier

from src.auth_tokens import create_access_token
from src.database.models import User
from src.database.session import SessionDep
from src.routes.models.srp import (
    SRPChallengeInput,
    SRPChallengeOutput,
    SRPProofInput,
    SRPProofOutput,
)
from src.srp_session_store import SrpSessionStore, get_srp_session_store, new_session_id

srp_router = APIRouter()

SrpStoreDep = Annotated[SrpSessionStore, Depends(get_srp_session_store)]

AUTH_FAILED = "Authentication failed"


@srp_router.post("/srp/challenge")
async def srp_challenge(
    input: SRPChallengeInput,
    session: SessionDep,
    srp_store: SrpStoreDep,
):
    session_id = new_session_id()
    result = await session.exec(select(User).where(User.username == input.username))
    user = result.first()
    if user is None:
        dummy_s = os.urandom(4)
        dummy_B = os.urandom(256)
        return SRPChallengeOutput(session_id=session_id, s=dummy_s, B=dummy_B)

    salt = user.salt
    verifier = user.verifier
    bytes_A = input.A
    svr = Verifier(input.username.encode(), salt, verifier, bytes_A)

    s, B = svr.get_challenge()
    if s is None or B is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_FAILED
        )

    bytes_b = svr.get_ephemeral_secret()
    await srp_store.store(session_id, input.username, bytes_A, bytes_b)

    return SRPChallengeOutput(session_id=session_id, s=s, B=B)


@srp_router.post("/srp/verify")
async def srp_proof(
    input: SRPProofInput,
    session: SessionDep,
    srp_store: SrpStoreDep,
):
    state = await srp_store.pop(input.session_id)
    if state is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_FAILED
        )
    username, bytes_A, bytes_b = state
    if username != input.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_FAILED
        )

    M_bytes = input.M

    result = await session.exec(select(User).where(User.username == username))
    user = result.first()
    if user is None or user.id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_FAILED
        )

    svr = Verifier(
        username.encode(),
        user.salt,
        user.verifier,
        bytes_A,
        bytes_b=bytes_b,
    )
    HAMK_bytes = svr.verify_session(M_bytes)

    if HAMK_bytes is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_FAILED
        )

    access_token = create_access_token(user.id)
    return SRPProofOutput(
        HAMK=HAMK_bytes,
        user_id=user.id,
        salt=user.salt,
        access_token=access_token,
    )
