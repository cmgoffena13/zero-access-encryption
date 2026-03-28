import pickle

import redis.asyncio as redis
from fastapi import Request
from srp import Verifier

SRP_SESSION_TTL_SECONDS = 600
KEY_PREFIX = "srp:verifier:"


def _key(username: str) -> str:
    return f"{KEY_PREFIX}{username}"


class SrpSessionStore:
    """Holds an optional async Redis client; if absent, uses an in-process dict."""

    def __init__(self, redis_client: redis.Redis | None) -> None:
        self._redis = redis_client
        self._memory: dict[str, Verifier] = {}

    async def store(self, username: str, svr: Verifier) -> None:
        if self._redis is not None:
            await self._redis.setex(
                _key(username), SRP_SESSION_TTL_SECONDS, pickle.dumps(svr)
            )
        else:
            self._memory[username] = svr

    async def pop(self, username: str) -> Verifier | None:
        if self._redis is not None:
            raw = await self._redis.getdel(_key(username))
            if raw is None:
                return None
            return pickle.loads(raw)
        return self._memory.pop(username, None)

    async def aclose(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()


def get_srp_session_store(request: Request) -> SrpSessionStore:
    return request.app.state.srp_session_store
