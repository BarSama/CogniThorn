import json
from fastapi import APIRouter
from shared.db.crud import get_all_settings, upsert_setting
from shared.redis_client import get_redis

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def list_settings():
    return await get_all_settings()


@router.put("")
async def update_settings(updates: dict[str, str]):
    """Update settings in DB and publish to Redis for worker hot-reload."""
    redis = get_redis()
    for key, value in updates.items():
        await upsert_setting(key, value)
    # Publish to workers via pub/sub
    await redis.publish("cognithhorn:config", json.dumps(updates))
    return {"updated": list(updates.keys())}
