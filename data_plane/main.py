"""CogniThorn WAF Worker — Data Plane entry point."""
import asyncio
import json
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

# Grace period after marking as draining before process exits.
# Long enough for the SSL Gateway to notice the "draining" status (~100ms pub/sub
# propagation) plus the longest expected in-flight request.
_DRAIN_SECONDS = 8


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
    """
    Graceful shutdown sequence:

    1. Mark this worker as "draining" in the Redis routing table.
       The SSL Gateway reads this on every request selection — within one
       round-trip (~100ms) it will stop sending new traffic here.

    2. Sleep for _DRAIN_SECONDS to let in-flight requests complete.
       Without this sleep, a request that was routed to us 10ms ago would
       receive a connection reset mid-response instead of a clean reply.

    3. Deregister from the control plane HTTP API (updates the DB).
       This is best-effort — if the control plane is also shutting down,
       the health checker will eventually clean up stale workers.

    Why we don't track in-flight count:
    Counting in-flight requests requires thread-safe atomics around every
    request entry/exit. For the typical rolling restart case (Docker scale-down
    during low traffic), an 8-second sleep achieves the same result more simply.
    For high-traffic deployments, replace the sleep with a real in-flight counter.
    """
    # Step 1: update Redis routing entry to "draining"
    try:
        from shared.redis_client import get_redis
        redis = get_redis()
        raw = await redis.hget("cognithhorn:workers", settings.worker_id)
        if raw:
            data = json.loads(raw)
            data["status"] = "draining"
            await redis.hset(
                "cognithhorn:workers",
                settings.worker_id,
                json.dumps(data),
            )
        logger.info("Worker %s marked as draining — stopping new traffic", settings.worker_id)
    except Exception as e:
        logger.warning("Could not mark worker as draining in Redis: %s", e)

    # Step 2: drain window
    logger.info("Draining in-flight requests (%ds window)...", _DRAIN_SECONDS)
    await asyncio.sleep(_DRAIN_SECONDS)

    # Step 3: deregister from control plane (best-effort)
    await registration.deregister()
    logger.info("WAF worker %s shutdown complete", settings.worker_id)


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok", "worker_id": settings.worker_id})
