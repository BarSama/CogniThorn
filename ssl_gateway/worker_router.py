"""
Routes decrypted HTTP requests directly to WAF workers via Redis registry.
The control plane is NOT in the hot path.
"""
import json
import logging
import httpx
from starlette.requests import Request
from starlette.responses import Response
from shared.redis_client import get_redis

logger = logging.getLogger(__name__)


async def get_workers() -> list[dict]:
    """Read worker registry from Redis hash."""
    redis = get_redis()
    raw = await redis.hgetall("cognithhorn:workers")
    workers = []
    for wid, data in raw.items():
        try:
            w = json.loads(data)
            if w.get("status") == "healthy":
                workers.append(w)
        except Exception:
            pass
    return workers


async def select_worker(workers: list[dict]) -> dict | None:
    """Round-robin worker selection using Redis INCR."""
    if not workers:
        return None
    redis = get_redis()
    idx = await redis.incr("cognithhorn:lb:counter")
    return workers[idx % len(workers)]


async def forward_to_worker(request: Request, body: bytes, upstream_url: str) -> Response:
    """
    Select a healthy worker, forward the request with X-CogniThorn-Upstream header.
    On failure, tries remaining workers before returning 503.
    """
    workers = await get_workers()
    if not workers:
        logger.error("No healthy workers available")
        return Response(content=b"No WAF workers available", status_code=503)

    worker = await select_worker(workers)
    remaining = [w for w in workers if w["id"] != worker["id"]] if worker else []

    for candidate in ([worker] if worker else []) + remaining:
        url = f"http://{candidate['host']}:{candidate['port']}{request.url.path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"

        headers = dict(request.headers)
        headers["X-CogniThorn-Upstream"] = upstream_url
        # Remove hop-by-hop headers
        for h in ["host", "content-length", "transfer-encoding", "connection"]:
            headers.pop(h, None)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body,
                )
            if resp.status_code not in (502, 503, 504):
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                )
            # Worker returned error — try next
            logger.warning("Worker %s returned %d, trying next", candidate["id"], resp.status_code)
            await _mark_worker_failed(candidate["id"])
        except Exception as e:
            logger.warning("Worker %s unreachable: %s", candidate["id"], e)
            await _mark_worker_failed(candidate["id"])

    return Response(content=b"All WAF workers unavailable", status_code=503)


async def _mark_worker_failed(worker_id: str) -> None:
    """Remove unhealthy worker from Redis routing table."""
    try:
        redis = get_redis()
        raw = await redis.hget("cognithhorn:workers", worker_id)
        if raw:
            data = json.loads(raw)
            data["status"] = "unhealthy"
            await redis.hset("cognithhorn:workers", worker_id, json.dumps(data))
    except Exception as e:
        logger.debug("Failed to mark worker unhealthy: %s", e)
