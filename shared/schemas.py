from datetime import datetime
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class RequestContext(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    method: str
    path: str
    query_string: str = ""
    headers: dict[str, str] = {}
    body: str = ""
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    upstream_url: Optional[str] = None  # from X-CogniThorn-Upstream header


class GuardResult(BaseModel):
    score: float
    passed: bool  # True if score < threshold


class Verdict(BaseModel):
    is_attack: bool
    attack_type: str  # sqli/xss/path_traversal/rce/none
    confidence: float
    explanation: str
    affected_parameter: Optional[str] = None
    remediation_hint: Optional[str] = None
    from_cache: bool = False


class IncidentCreate(BaseModel):
    request_id: str
    method: str
    path: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    guard_score: float
    is_attack: Optional[bool] = None
    attack_type: Optional[str] = None
    confidence: Optional[float] = None
    explanation: Optional[str] = None
    affected_parameter: Optional[str] = None
    remediation_hint: Optional[str] = None
    action_taken: str = "pass"  # pass/block/allow_fp
    pr_url: Optional[str] = None
    worker_id: Optional[str] = None
    raw_request: Optional[dict] = None  # only for blocked incidents


class IncidentRead(IncidentCreate):
    id: int
    created_at: datetime


class WorkerInfo(BaseModel):
    id: str
    host: str
    port: int
    status: str = "healthy"
    last_seen: Optional[datetime] = None


class DomainCreate(BaseModel):
    fqdn: str
    upstream_url: str


class DomainRead(DomainCreate):
    acme_status: str = "pending"
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
