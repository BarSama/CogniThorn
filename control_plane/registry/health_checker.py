"""Background task: ping every registered worker every 10 seconds."""
import asyncio
import logging
import httpx
from control_plane.registry.registry import get_registry, deregister_worker, mark_worker_unhealthy

logger = logging.getLogger(__name__)

_failure_counts: dict[str, int] = {}
MAX_FAILURES = 3


async def run_health_checks() -> None:
    """Run forever, health-checking all workers every 10s."""
    while True:
        await asyncio.sleep(10)
        try:
            workers = await get_registry()
            tasks = [_check_worker(w) for w in workers]
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error("Health check cycle error: %s", e)


async def _check_worker(worker: dict) -> None:
    wid = worker["id"]
    url = f"http://{worker['host']}:{worker['port']}/health"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                _failure_counts[wid] = 0
                return
    except Exception:
        pass

    _failure_counts[wid] = _failure_counts.get(wid, 0) + 1
    count = _failure_counts[wid]
    logger.warning("Worker %s health check failed (%d/%d)", wid, count, MAX_FAILURES)

    if count >= MAX_FAILURES:
        logger.error("Worker %s marked unhealthy and removed from routing", wid)
        await mark_worker_unhealthy(wid)
        await deregister_worker(wid)
        _failure_counts.pop(wid, None)
