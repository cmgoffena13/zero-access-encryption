"""JWT access tokens for data API (issued after register or SRP verify)."""

from datetime import datetime, timedelta, timezone

import jwt

from src.settings import BaseConfig, get_config


def _secret() -> str:
    return get_config(BaseConfig().ENV_STATE).JWT_SECRET


def create_access_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def user_id_from_token(token: str) -> int:
    payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    return int(payload["sub"])
