import json
from fastapi import APIRouter, HTTPException
from shared.db.crud import upsert_domain, get_all_domains, get_domain
from shared.schemas import DomainCreate
from shared.redis_client import get_redis

router = APIRouter(prefix="/api/domains", tags=["domains"])


@router.get("")
async def list_domains():
    rows = await get_all_domains()
    return [dict(r) for r in rows]


@router.post("")
async def add_domain(d: DomainCreate):
    await upsert_domain(d)
    # Publish to Redis for SSL Gateway to pick up
    redis = get_redis()
    await redis.hset(
        f"cognithhorn:domain:{d.fqdn}",
        mapping={"upstream_url": d.upstream_url, "acme_status": "pending"},
    )
    return {"fqdn": d.fqdn, "status": "pending_cert"}


@router.get("/{fqdn}")
async def get_one_domain(fqdn: str):
    row = await get_domain(fqdn)
    if not row:
        raise HTTPException(status_code=404, detail="Domain not found")
    return dict(row)
