import json
from fastapi import APIRouter, HTTPException, Request
from shared.db.crud import upsert_domain, get_all_domains, get_domain, write_audit_log
from shared.schemas import DomainCreate
from shared.redis_client import get_redis

router = APIRouter(prefix="/api/domains", tags=["domains"])


@router.get("")
async def list_domains():
    rows = await get_all_domains()
    return [dict(r) for r in rows]


@router.post("")
async def add_domain(d: DomainCreate, request: Request):
    # DomainCreate.block_ssrf validator already ran — upstream_url is safe
    await upsert_domain(d)
    redis = get_redis()
    await redis.hset(
        f"cognithhorn:domain:{d.fqdn}",
        mapping={"upstream_url": d.upstream_url, "acme_status": "pending"},
    )
    await write_audit_log(
        actor=request.client.host if request.client else "unknown",
        action="domain.add",
        resource=d.fqdn,
        detail={"upstream_url": d.upstream_url},
    )
    return {"fqdn": d.fqdn, "status": "pending_cert"}


@router.get("/{fqdn}")
async def get_one_domain(fqdn: str):
    row = await get_domain(fqdn)
    if not row:
        raise HTTPException(status_code=404, detail="Domain not found")
    return dict(row)
