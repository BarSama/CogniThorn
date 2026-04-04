import json
from fastapi import APIRouter, Request
from shared.db.crud import get_all_settings, upsert_setting, write_audit_log
from shared.redis_client import get_redis

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def list_settings():
    return await get_all_settings()


@router.put("")
async def update_settings(updates: dict[str, str], request: Request):
    """Update settings in DB and publish to Redis for worker hot-reload."""
    redis = get_redis()
    current = await get_all_settings()
    for key, value in updates.items():
        await upsert_setting(key, value)
        # Audit each key individually so the log is searchable by resource
        await write_audit_log(
            actor=request.client.host if request.client else "unknown",
            action="settings.update",
            resource=key,
            detail={"old": current.get(key), "new": value},
        )
    await redis.publish("cognithhorn:config", json.dumps(updates))
    return {"updated": list(updates.keys())}
