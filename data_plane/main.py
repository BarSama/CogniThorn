"""CogniThorn WAF Worker — Data Plane entry point."""
import asyncio
import logging

from fastapi import FastAPI
from starlette.responses import JSONResponse

from data_plane.proxy.middleware import WAFMiddleware
from data_plane.detection.guard import get_session  # preload ONNX on startup
from data_plane.worker import config_subscriber, registration
from shared.config.settings import settings
from shared.db.database import run_migrations

logger = logging.getLogger(__name__)

app = FastAPI(title="CogniThorn WAF Worker", docs_url=None, redoc_url=None)

# Attach WAF middleware (processes every request)
app.add_middleware(WAFMiddleware)


@app.on_event("startup")
async def startup():
    # 1. Run DB migrations (idempotent)
    try:
        await run_migrations()
    except Exception as e:
        logger.warning("DB migration skipped (may already be done): %s", e)

    # 2. Preload ONNX model + warmup
    try:
        get_session()
    except Exception as e:
        logger.critical("Failed to load ONNX model: %s — worker will fail-open on all requests", e)

    # 3. Start Redis config subscriber
    asyncio.create_task(config_subscriber.start_subscriber())

    # 4. Register with control plane
    asyncio.create_task(registration.register())

    logger.info("WAF worker started (id=%s, port=%s)", settings.worker_id, settings.worker_port)


@app.on_event("shutdown")
async def shutdown():
    asyncio.create_task(registration.deregister())


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok", "worker_id": settings.worker_id})
