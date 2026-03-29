"""CogniThorn Control Plane — Management API entry point."""
import asyncio
import logging

from fastapi import FastAPI
from starlette.responses import JSONResponse

from control_plane.api.incidents import router as incidents_router
from control_plane.api.settings_api import router as settings_router
from control_plane.api.workers_api import router as workers_router
from control_plane.api.domains_api import router as domains_router
from control_plane.api.healing_api import router as healing_router
from control_plane.registry.health_checker import run_health_checks
from shared.db.database import run_migrations
from shared.db.setup import seed_default_settings

logger = logging.getLogger(__name__)

app = FastAPI(title="CogniThorn Control Plane", version="0.1.0")

app.include_router(incidents_router)
app.include_router(settings_router)
app.include_router(workers_router)
app.include_router(domains_router)
app.include_router(healing_router)


@app.on_event("startup")
async def startup():
    await run_migrations()
    await seed_default_settings()
    asyncio.create_task(run_health_checks())
    logger.info("Control plane started")


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok", "service": "control-plane"})
