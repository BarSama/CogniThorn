"""
Subscribe to Redis 'cognithhorn:config' channel.
Updates local in-memory config when control plane publishes changes.
"""
import asyncio
import json
import logging
from shared.config.settings import settings
from shared.redis_client import get_redis

logger = logging.getLogger(__name__)

# In-memory config cache (updated by pub/sub listener)
_config = {
    "sensitivity_threshold": settings.sensitivity_threshold,
}
_lock = asyncio.Lock()


def get_threshold() -> float:
    return _config.get("sensitivity_threshold", settings.sensitivity_threshold)


async def start_subscriber() -> None:
    """Run forever, listening for config changes on Redis pub/sub."""
    while True:
        try:
            redis = get_redis()
            pubsub = redis.pubsub()
            await pubsub.subscribe("cognithhorn:config")
            logger.info("Subscribed to cognithhorn:config channel")

            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        async with _lock:
                            _config.update(data)
                        logger.info("Config updated: %s", data)
                    except Exception as e:
                        logger.warning("Failed to parse config message: %s", e)
        except Exception as e:
            logger.error("Redis subscriber error, reconnecting in 5s: %s", e)
            await asyncio.sleep(5)
