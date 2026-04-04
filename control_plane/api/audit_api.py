"""Audit log API — read-only view of all control plane mutations."""
from fastapi import APIRouter, Query
from shared.db.crud import get_audit_log

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def list_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    rows = await get_audit_log(limit=limit, offset=offset)
    return [dict(r) for r in rows]
