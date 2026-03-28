from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from rich import panel, print
from scalar_fastapi import get_scalar_api_reference

from src.database.session import engine, setup_database, test_connection
from src.logging_conf import setup_logging
from src.routes.data import data_router
from src.routes.register import register_router
from src.routes.srp import srp_router
from src.types import ORJSONResponse

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(panel.Panel("Server is starting up...", border_style="green"))
    setup_logging()
    await setup_database()
    await test_connection()
    yield
    print(panel.Panel("Server is shutting down...", border_style="red"))
    await engine.dispose()


app = FastAPI(lifespan=lifespan, default_response_class=ORJSONResponse)

app.include_router(register_router)
app.include_router(srp_router)
app.include_router(data_router)

if STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="static_assets")


@app.get("/")
async def index():
    index_path = STATIC_DIR / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return {"status": "ok", "message": "Add static/index.html for the POC UI"}


@app.get("/health")
async def heartbeat():
    return {"status": "ok"}


@app.get("/scalar", include_in_schema=False)
async def get_scalar_docs():
    return get_scalar_api_reference(openapi_url=app.openapi_url, title="Scalar API")
