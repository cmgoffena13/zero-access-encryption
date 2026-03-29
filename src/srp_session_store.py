"""SRP verifier state between challenge and verify.

Stores JSON-serializable fields to reconstruct ``Verifier``: username, client A, server b.
Keyed by opaque session_id.
"""

from __future__ import annotations

import json
import secrets
from base64 import b64decode, b64encode

import redis.asyncio as redis
from fastapi import Request

SRP_SESSION_TTL_SECONDS = 600
KEY_PREFIX = "srp:session:"


def new_session_id() -> str:
    return secrets.token_urlsafe(32)


def _redis_key(session_id: str) -> str:
    return f"{KEY_PREFIX}{session_id}"


def pack_session(username: str, bytes_A: bytes, bytes_b: bytes) -> bytes:
    return json.dumps(
        {
            "username": username,
            "A": b64encode(bytes_A).decode("ascii"),
            "b": b64encode(bytes_b).decode("ascii"),
        }
    ).encode("utf-8")


def unpack_session(raw: bytes) -> tuple[str, bytes, bytes]:
    obj = json.loads(raw.decode("utf-8"))
    return obj["username"], b64decode(obj["A"]), b64decode(obj["b"])


class SrpSessionStore:
    """Holds an optional async Redis client; if absent, uses an in-process dict."""

    def __init__(self, redis_client: redis.Redis | None) -> None:
        self._redis = redis_client
        self._memory: dict[str, bytes] = {}

    async def store(
        self, session_id: str, username: str, bytes_A: bytes, bytes_b: bytes
    ) -> None:
        payload = pack_session(username, bytes_A, bytes_b)
        if self._redis is not None:
            await self._redis.setex(
                _redis_key(session_id), SRP_SESSION_TTL_SECONDS, payload
            )
        else:
            self._memory[session_id] = payload

    async def pop(self, session_id: str) -> tuple[str, bytes, bytes] | None:
        if self._redis is not None:
            raw = await self._redis.getdel(_redis_key(session_id))
            if raw is None:
                return None
            return unpack_session(raw)
        raw = self._memory.pop(session_id, None)
        if raw is None:
            return None
        return unpack_session(raw)

    async def aclose(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()


def get_srp_session_store(request: Request) -> SrpSessionStore:
    return request.app.state.srp_session_store
