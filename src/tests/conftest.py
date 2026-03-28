import os

# Needs to happen before local imports
os.environ["ENV_STATE"] = "test"

from typing import AsyncGenerator, Generator

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app import app
from src.database.models import (  # noqa: F401 — register models on SQLModel metadata
    User,
    UserData,
)
from src.database.session import async_session_factory, engine, get_session


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Fresh async session for a single test (closes after the test)."""
    async with async_session_factory() as session:
        yield session


@pytest.fixture
async def override_get_session(db_session: AsyncSession):
    """Route `get_session` uses the test `db_session` so HTTP tests share one session."""

    async def _override() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_session] = _override
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
async def truncate_tables():
    yield
    try:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM user_data"))
            await conn.execute(text("DELETE FROM users"))
    except Exception as e:
        print(f"Warning: failed to truncate tables: {e}")


@pytest.fixture(autouse=True)
def clear_srp_sessions():
    yield
    from src.routes.srp import srp_sessions

    srp_sessions.clear()


@pytest.fixture()
async def async_client(client: TestClient) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url=str(client.base_url),
    ) as ac:
        yield ac


__all__ = [
    "anyio_backend",
    "app",
    "async_client",
    "client",
    "db_session",
    "override_get_session",
]
