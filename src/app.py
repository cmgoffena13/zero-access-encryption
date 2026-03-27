from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from rich import panel, print
from scalar_fastapi import get_scalar_api_reference

from src.database.session import engine, test_connection
from src.logging_conf import setup_logging
from src.types import ORJSONResponse

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(panel.Panel("Server is starting up...", border_style="green"))
    setup_logging()
    await test_connection()
    yield
    print(panel.Panel("Server is shutting down...", border_style="red"))
    await engine.dispose()


app = FastAPI(lifespan=lifespan, default_response_class=ORJSONResponse)


@app.get("/")
async def heartbeat():
    return {"status": "ok"}


@app.get("/scalar", include_in_schema=False)
async def get_scalar_docs():
    return get_scalar_api_reference(openapi_url=app.openapi_url, title="Scalar API")
