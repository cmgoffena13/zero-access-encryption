from typing import Annotated

import structlog
from fastapi import Depends
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel, text
from sqlmodel.ext.asyncio.session import AsyncSession

from src.database.models import User, UserData  # noqa: F401
from src.settings import get_database_config

logger = structlog.get_logger(__name__)

db_config = get_database_config()

_url = db_config["sqlalchemy.url"]
_engine_kw: dict = {
    "echo": db_config["sqlalchemy.echo"],
    "future": db_config["sqlalchemy.future"],
    "connect_args": db_config.get("sqlalchemy.connect_args", {}),
}
if not _url.startswith("sqlite"):
    _engine_kw["pool_size"] = db_config.get("sqlalchemy.pool_size", 20)
    _engine_kw["max_overflow"] = db_config.get("sqlalchemy.max_overflow", 10)
    _engine_kw["pool_timeout"] = db_config.get("sqlalchemy.pool_timeout", 30)

engine = create_async_engine(_url, **_engine_kw)

async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def test_connection():
    logger.info("Testing Database Connection")
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Test Successful")
    except Exception as e:
        logger.critical(f"Database Connection Failed: {e}")
        raise


async def get_session():
    async with async_session_factory() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def setup_database():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
