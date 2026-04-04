from fastapi import APIRouter, HTTPException, Request
from control_plane.registry.registry import register_worker, deregister_worker, get_registry
from shared.db.crud import write_audit_log
from shared.schemas import WorkerInfo

router = APIRouter(prefix="/api/workers", tags=["workers"])


@router.get("")
async def list_workers():
    return await get_registry()


@router.post("/register")
async def register(w: WorkerInfo, request: Request):
    await register_worker(w)
    await write_audit_log(
        actor=request.client.host if request.client else "unknown",
        action="worker.register",
        resource=w.id,
        detail={"host": w.host, "port": w.port},
    )
    return {"registered": w.id}


@router.delete("/{worker_id}")
async def deregister(worker_id: str, request: Request):
    await deregister_worker(worker_id)
    await write_audit_log(
        actor=request.client.host if request.client else "unknown",
        action="worker.deregister",
        resource=worker_id,
    )
    return {"deregistered": worker_id}
