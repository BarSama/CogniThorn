from fastapi import APIRouter, HTTPException, Query
from shared.db.crud import get_incidents, get_incident, update_incident_pr

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("")
async def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    attack_type: str | None = Query(None),
):
    rows = await get_incidents(limit=limit, offset=offset, attack_type=attack_type)
    return [dict(r) for r in rows]


@router.get("/{incident_id}")
async def get_one_incident(incident_id: int):
    row = await get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return dict(row)
