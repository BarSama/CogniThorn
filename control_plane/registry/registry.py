"""Worker registry — writes to both PostgreSQL (audit) and Redis (live routing)."""
import json
import logging
from datetime import datetime
from shared.redis_client import get_redis
from shared.db.crud import upsert_worker, delete_worker
from shared.schemas import WorkerInfo

logger = logging.getLogger(__name__)

WORKER_TTL = 60  # Redis TTL seconds; workers must heartbeat to stay alive


async def register_worker(w: WorkerInfo) -> None:
    redis = get_redis()
    # Store in Redis hash (used by SSL Gateway for routing)
    worker_data = json.dumps({
        "id": w.id, "host": w.host, "port": w.port,
        "status": w.status, "last_seen": datetime.utcnow().isoformat(),
    })
    await redis.hset("cognithhorn:workers", w.id, worker_data)
    # Mirror to PostgreSQL for audit/dashboard
    await upsert_worker(w)
    logger.info("Worker registered: %s @ %s:%s", w.id, w.host, w.port)


async def deregister_worker(worker_id: str) -> None:
    redis = get_redis()
    await redis.hdel("cognithhorn:workers", worker_id)
    await delete_worker(worker_id)
    logger.info("Worker deregistered: %s", worker_id)


async def get_registry() -> list[dict]:
    redis = get_redis()
    raw = await redis.hgetall("cognithhorn:workers")
    workers = []
    for wid, data in raw.items():
        try:
            workers.append(json.loads(data))
        except Exception:
            pass
    return workers


async def mark_worker_unhealthy(worker_id: str) -> None:
    redis = get_redis()
    raw = await redis.hget("cognithhorn:workers", worker_id)
    if raw:
        data = json.loads(raw)
        data["status"] = "unhealthy"
        await redis.hset("cognithhorn:workers", worker_id, json.dumps(data))
    from shared.db.crud import upsert_worker
    await upsert_worker(WorkerInfo(id=worker_id, host="", port=0, status="unhealthy"))
