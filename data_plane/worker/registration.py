"""Register this worker with the control plane on startup."""
import asyncio
import logging
import socket
import httpx
from shared.config.settings import settings

logger = logging.getLogger(__name__)


async def register() -> None:
    """POST registration to control plane. Retries with backoff."""
    worker_id = settings.worker_id or socket.gethostname()
    hostname = socket.gethostname()
    payload = {
        "id": worker_id,
        "host": hostname,
        "port": settings.worker_port,
        "status": "healthy",
    }
    url = f"{settings.control_plane_url}/api/workers/register"
    for attempt in range(5):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
            logger.info("Registered with control plane as worker %s", worker_id)
            return
        except Exception as e:
            wait = 2 ** attempt
            logger.warning("Registration attempt %d failed: %s. Retrying in %ds", attempt + 1, e, wait)
            await asyncio.sleep(wait)
    logger.error("Failed to register with control plane after 5 attempts. Continuing anyway.")


async def deregister() -> None:
    """DELETE this worker from the control plane registry on shutdown."""
    worker_id = settings.worker_id or socket.gethostname()
    url = f"{settings.control_plane_url}/api/workers/{worker_id}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.delete(url)
        logger.info("Deregistered worker %s", worker_id)
    except Exception as e:
        logger.warning("Deregistration failed: %s", e)
