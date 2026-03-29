import asyncio
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from shared.db.crud import get_incident
from control_plane.healing.patch_generator import run_self_healing

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["healing"])


@router.post("/{incident_id}/heal")
async def trigger_healing(incident_id: int, background_tasks: BackgroundTasks):
    row = await get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident = dict(row)
    if not incident.get("attack_type") or incident.get("action_taken") != "block":
        raise HTTPException(status_code=400, detail="Incident is not a confirmed attack")
    background_tasks.add_task(run_self_healing, incident)
    return {"status": "healing_triggered", "incident_id": incident_id}
