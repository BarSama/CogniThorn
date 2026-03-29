import logging

import redis.asyncio as aioredis
from redis.asyncio.sentinel import Sentinel

from shared.config.settings import settings

logger = logging.getLogger(__name__)

_sentinel: Sentinel | None = None
_direct: aioredis.Redis | None = None


def _parse_sentinel_hosts() -> list[tuple[str, int]]:
    hosts = []
    for entry in settings.redis_sentinel_hosts.split(","):
        entry = entry.strip()
        if ":" in entry:
            host, port = entry.rsplit(":", 1)
            hosts.append((host, int(port)))
        else:
            hosts.append((entry, 26379))
    return hosts


def get_redis() -> aioredis.Redis:
    """Return master Redis client via Sentinel."""
    global _sentinel
    if _sentinel is None:
        hosts = _parse_sentinel_hosts()
        _sentinel = Sentinel(
            hosts,
            sentinel_kwargs={"password": settings.redis_password},
            password=settings.redis_password,
            decode_responses=True,
        )
    return _sentinel.master_for(settings.redis_master_name)


def get_redis_replica() -> aioredis.Redis:
    """Return read-only slave Redis client via Sentinel."""
    global _sentinel
    if _sentinel is None:
        get_redis()  # initialize
    return _sentinel.slave_for(settings.redis_master_name)
