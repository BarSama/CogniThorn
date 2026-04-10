"""Core WAF middleware: intercept, score, block or forward."""
import asyncio
import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from data_plane.detection import guard, analyst
from data_plane.proxy import forwarder, request_parser
from shared.config.settings import settings
from shared.db.crud import log_incident_blocked
from shared.redis_client import get_redis
from shared.schemas import IncidentCreate

logger = logging.getLogger(__name__)


class WAFMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next) -> Response:
        # Buffer body so we can read it and re-use it
        body = await request.body()

        # Parse request into a clean context object
        ctx = await request_parser.parse_request(request, body)

        # ── Fast Path ──────────────────────────────────────────────────────
        threshold = await _get_threshold()
        guard_result = await guard.score(ctx, threshold)

        if guard_result.passed:
            # Clean traffic: increment Redis counters only, never touch DB
            asyncio.create_task(_increment_counters())
            return await forwarder.forward(ctx, body)

        # ── Deep Path ─────────────────────────────────────────────────────
        verdict = await analyst.analyze(ctx)

        if not verdict.is_attack:
            # False positive — pass through
            asyncio.create_task(_increment_counters(false_positive=True))
            return await forwarder.forward(ctx, body)

        # ── Confirmed Attack — Block ───────────────────────────────────────
        asyncio.create_task(_log_blocked(ctx, guard_result.score, verdict))
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "attack_type": verdict.attack_type,
                "explanation": verdict.explanation,
                "request_id": ctx.request_id,
            },
        )


async def _get_threshold() -> float:
    """Read sensitivity_threshold from Redis config (updated via pub/sub)."""
    # Workers maintain a local copy updated by config_subscriber
    from data_plane.worker import config_subscriber
    return config_subscriber.get_threshold()


async def _increment_counters(false_positive: bool = False) -> None:
    """
    Increment Redis stats counters using a pipeline.

    Why a pipeline?
    Each individual INCR is a round-trip to Redis (~0.3–0.5ms on localhost,
    more on a real network). At 1000 req/s with 2 INCRs each = 2000 round-trips
    per second = up to 1 full second of Redis latency per second.
    A pipeline batches all commands into one round-trip regardless of count.
    `transaction=False` means no MULTI/EXEC wrapper — pure command batching,
    which is safe for non-atomic counter increments.
    """
    try:
        redis = get_redis()
        async with redis.pipeline(transaction=False) as pipe:
            pipe.incr("cognithhorn:stats:requests_total")
            if false_positive:
                pipe.incr("cognithhorn:stats:false_positives_total")
            else:
                pipe.incr("cognithhorn:stats:requests_clean")
            await pipe.execute()
    except Exception as e:
        logger.debug("Counter increment failed: %s", e)


async def _log_blocked(ctx, guard_score: float, verdict) -> None:
    try:
        redis = get_redis()
        async with redis.pipeline(transaction=False) as pipe:
            pipe.incr("cognithhorn:stats:requests_total")
            pipe.incr("cognithhorn:stats:requests_blocked")
            await pipe.execute()

        inc = IncidentCreate(
            request_id=ctx.request_id,
            method=ctx.method,
            path=ctx.path,
            source_ip=ctx.source_ip,
            user_agent=ctx.user_agent,
            guard_score=guard_score,
            is_attack=True,
            attack_type=verdict.attack_type,
            confidence=verdict.confidence,
            explanation=verdict.explanation,
            affected_parameter=verdict.affected_parameter,
            remediation_hint=verdict.remediation_hint,
            action_taken="block",
            worker_id=settings.worker_id,
            raw_request={
                "method": ctx.method,
                "path": ctx.path,
                "query_string": ctx.query_string,
                "headers": ctx.headers,
                "body": ctx.body,
            },
        )
        await log_incident_blocked(inc)
    except Exception as e:
        logger.error("Failed to log blocked incident: %s", e, exc_info=True)
