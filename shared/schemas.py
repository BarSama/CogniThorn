import ipaddress
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


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

    @field_validator("upstream_url")
    @classmethod
    def block_ssrf(cls, v: str) -> str:
        """
        Reject upstream_url values that point to private / loopback networks.

        --- What is SSRF? ---
        Server-Side Request Forgery (SSRF) means tricking the server into
        making HTTP requests to internal addresses. If an attacker adds
        upstream_url=http://169.254.169.254/latest/meta-data/ they can use
        CogniThorn to read the AWS EC2 metadata service — which often contains
        IAM credentials.

        --- What we check ---
        We parse the hostname from the URL and try to interpret it as an IP
        address. If it's in a private range, we reject it.

        Private ranges blocked:
          10.0.0.0/8      — RFC 1918 private
          172.16.0.0/12   — RFC 1918 private
          192.168.0.0/16  — RFC 1918 private
          127.0.0.0/8     — loopback
          169.254.0.0/16  — link-local (AWS/GCP metadata)
          ::1             — IPv6 loopback
          fc00::/7        — IPv6 unique local

        --- Known limitation (flag for learners) ---
        This only catches IP *literals* in the URL. If an attacker uses
        http://evil.com where evil.com resolves to 169.254.x.x, we won't
        catch it here. That's a DNS rebinding attack — mitigating it requires
        resolving the hostname at request time (in the forwarder). Tracked in
        Phase 4 of the roadmap.
        """
        _BLOCKED_HOSTNAMES = {"localhost", "0.0.0.0", "[::]", "::"}
        _PRIVATE_NETWORKS = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
        ]

        try:
            parsed = urlparse(v)
            host = parsed.hostname or ""
        except Exception:
            raise ValueError(f"Invalid upstream_url: {v!r}")

        if not host:
            raise ValueError("upstream_url must include a hostname.")

        if host.lower() in _BLOCKED_HOSTNAMES:
            raise ValueError(
                f"upstream_url hostname {host!r} is not allowed "
                "(loopback/any-address)."
            )

        # Strip IPv6 brackets before parsing
        host_clean = host.strip("[]")
        try:
            addr = ipaddress.ip_address(host_clean)
            for net in _PRIVATE_NETWORKS:
                if addr in net:
                    raise ValueError(
                        f"upstream_url points to a private/reserved address "
                        f"({addr}). This is blocked to prevent SSRF attacks."
                    )
        except ValueError as e:
            # Re-raise if it's our SSRF error, otherwise it's just not an IP
            # literal (a hostname like "myapp") — that's fine
            if "SSRF" in str(e) or "private" in str(e) or "loopback" in str(e) or "not allowed" in str(e):
                raise
        return v


class DomainRead(DomainCreate):
    acme_status: str = "pending"
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
