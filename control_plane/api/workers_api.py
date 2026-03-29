from fastapi import APIRouter, HTTPException
from control_plane.registry.registry import register_worker, deregister_worker, get_registry
from shared.schemas import WorkerInfo

router = APIRouter(prefix="/api/workers", tags=["workers"])


@router.get("")
async def list_workers():
    return await get_registry()


@router.post("/register")
async def register(w: WorkerInfo):
    await register_worker(w)
    return {"registered": w.id}


@router.delete("/{worker_id}")
async def deregister(worker_id: str):
    await deregister_worker(worker_id)
    return {"deregistered": worker_id}
