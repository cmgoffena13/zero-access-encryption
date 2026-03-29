import uuid
from functools import lru_cache
from typing import Literal, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class BaseConfig(BaseSettings):
    ENV_STATE: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class GlobalConfig(BaseConfig):
    LOG_LEVEL: LogLevel = "INFO"
    DATABASE_URL: Optional[str] = None
    REDIS_URL: Optional[str] = None
    JWT_SECRET: str = "dev-only-jwt-secret-min-32-chars-long-change-in-prod"


class DevConfig(GlobalConfig):
    LOG_LEVEL: LogLevel = "DEBUG"

    model_config = SettingsConfigDict(env_prefix="DEV_")


class TestConfig(GlobalConfig):
    DATABASE_URL: Optional[str] = "sqlite+aiosqlite:///:memory:"

    model_config = SettingsConfigDict(env_prefix="TEST_")


class ProdConfig(GlobalConfig):
    LOG_LEVEL: LogLevel = "ERROR"

    model_config = SettingsConfigDict(env_prefix="PROD_")


@lru_cache()
def get_config(env_state: str):
    if not env_state:
        raise ValueError("ENV_STATE is not set. Possible values are: DEV, TEST, PROD")
    env_state = env_state.lower()

    configs = {"dev": DevConfig, "prod": ProdConfig, "test": TestConfig}
    return configs[env_state]()


config = get_config(BaseConfig().ENV_STATE)


def get_database_config():
    """Get database configuration for both SQLAlchemy and Alembic"""
    env_state = BaseConfig().ENV_STATE
    db_config = get_config(env_state)

    if db_config.DATABASE_URL is None:
        prefix_by_env = {"dev": "DEV_", "test": "TEST_", "prod": "PROD_"}
        env_key = (env_state or "").lower()
        env_prefix = prefix_by_env.get(env_key, "")
        raise ValueError(
            f"{env_prefix}DATABASE_URL is not set for the {env_state} environment"
        )

    config_dict = {
        "sqlalchemy.url": db_config.DATABASE_URL,
        "sqlalchemy.echo": True if isinstance(config, DevConfig) else False,
        "sqlalchemy.future": True,
        "sqlalchemy.pool_size": 20,
        "sqlalchemy.max_overflow": 10,
        "sqlalchemy.pool_timeout": 30,
    }

    # Add database-specific connect args
    if db_config.DATABASE_URL.startswith("sqlite"):
        config_dict["sqlalchemy.connect_args"] = {"check_same_thread": False}
    elif isinstance(db_config, TestConfig):
        # PostgreSQL settings for pgbouncer compatibility in test environment
        config_dict["sqlalchemy.connect_args"] = {
            "statement_cache_size": 0,
            "prepared_statement_cache_size": 0,
            "prepared_statement_name_func": lambda: f"__asyncpg_{uuid.uuid4()}__",
            "command_timeout": 60,  # Increase timeout for test teardown
        }

    return config_dict
