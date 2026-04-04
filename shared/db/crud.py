import hashlib
import json
from datetime import datetime

from sqlalchemy import desc, func, insert, select, update

from shared.db.database import get_conn
from shared.db.models import (
    audit_log_table,
    domains_table,
    incidents,
    settings_table,
    stats_cache_table,
    workers_table,
)
from shared.schemas import DomainCreate, IncidentCreate, WorkerInfo

# ── Incidents ──────────────────────────────────────────────────────────────


async def log_incident_blocked(inc: IncidentCreate) -> None:
    """Write full incident row to DB. ONLY called for blocked/malicious requests."""
    async with get_conn() as conn:
        await conn.execute(
            insert(incidents).values(
                request_id=inc.request_id,
                method=inc.method,
                path=inc.path,
                source_ip=inc.source_ip,
                user_agent=inc.user_agent,
                guard_score=inc.guard_score,
                is_attack=inc.is_attack,
                attack_type=inc.attack_type,
                confidence=inc.confidence,
                explanation=inc.explanation,
                affected_parameter=inc.affected_parameter,
                remediation_hint=inc.remediation_hint,
                action_taken=inc.action_taken,
                worker_id=inc.worker_id,
                raw_request=inc.raw_request,
            )
        )
        await conn.commit()


async def get_incidents(
    limit: int = 50, offset: int = 0, attack_type: str | None = None
):
    async with get_conn() as conn:
        q = (
            select(incidents)
            .order_by(desc(incidents.c.created_at))
            .limit(limit)
            .offset(offset)
        )
        if attack_type:
            q = q.where(incidents.c.attack_type == attack_type)
        result = await conn.execute(q)
        return result.mappings().all()


async def get_incident(incident_id: int):
    async with get_conn() as conn:
        result = await conn.execute(
            select(incidents).where(incidents.c.id == incident_id)
        )
        return result.mappings().first()


async def update_incident_pr(incident_id: int, pr_url: str) -> None:
    async with get_conn() as conn:
        await conn.execute(
            update(incidents)
            .where(incidents.c.id == incident_id)
            .values(pr_url=pr_url)
        )
        await conn.commit()


# ── Settings ───────────────────────────────────────────────────────────────


async def get_all_settings() -> dict[str, str]:
    async with get_conn() as conn:
        result = await conn.execute(select(settings_table))
        return {row.key: row.value for row in result}


async def get_setting(key: str) -> str | None:
    async with get_conn() as conn:
        result = await conn.execute(
            select(settings_table.c.value).where(settings_table.c.key == key)
        )
        row = result.first()
        return row[0] if row else None


async def upsert_setting(key: str, value: str) -> None:
    async with get_conn() as conn:
        await conn.execute(
            settings_table.insert()
            .on_conflict_do_update(
                index_elements=["key"],
                set_={"value": value, "updated_at": func.now()},
            )
            .values(key=key, value=value)
        )
        await conn.commit()


# ── Workers ────────────────────────────────────────────────────────────────


async def upsert_worker(w: WorkerInfo) -> None:
    async with get_conn() as conn:
        await conn.execute(
            workers_table.insert()
            .on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "host": w.host,
                    "port": w.port,
                    "status": w.status,
                    "last_seen": func.now(),
                },
            )
            .values(id=w.id, host=w.host, port=w.port, status=w.status)
        )
        await conn.commit()


async def delete_worker(worker_id: str) -> None:
    from sqlalchemy import delete as sql_delete

    async with get_conn() as conn:
        await conn.execute(
            sql_delete(workers_table).where(workers_table.c.id == worker_id)
        )
        await conn.commit()


async def get_workers() -> list:
    async with get_conn() as conn:
        result = await conn.execute(select(workers_table))
        return result.mappings().all()


# ── Domains ────────────────────────────────────────────────────────────────


async def upsert_domain(d: DomainCreate) -> None:
    async with get_conn() as conn:
        await conn.execute(
            domains_table.insert()
            .on_conflict_do_update(
                index_elements=["fqdn"],
                set_={"upstream_url": d.upstream_url},
            )
            .values(fqdn=d.fqdn, upstream_url=d.upstream_url)
        )
        await conn.commit()


async def get_domain(fqdn: str):
    from shared.crypto import decrypt_pem
    async with get_conn() as conn:
        result = await conn.execute(
            select(domains_table).where(domains_table.c.fqdn == fqdn)
        )
        row = result.mappings().first()
        if row is None:
            return None
        # Decrypt key_pem transparently — callers never see raw ciphertext
        row = dict(row)
        row["key_pem"] = decrypt_pem(row.get("key_pem"))
        return row


async def get_all_domains() -> list:
    from shared.crypto import decrypt_pem
    async with get_conn() as conn:
        result = await conn.execute(select(domains_table))
        rows = result.mappings().all()
        # Decrypt key_pem on each row; suppress key material in list responses
        # by returning None — full key only available via get_domain(fqdn)
        return [
            {**dict(r), "key_pem": None}
            for r in rows
        ]


async def update_domain_cert(
    fqdn: str, cert_pem: str, key_pem: str, expires_at: datetime
) -> None:
    from shared.crypto import encrypt_pem
    async with get_conn() as conn:
        await conn.execute(
            update(domains_table)
            .where(domains_table.c.fqdn == fqdn)
            .values(
                cert_pem=cert_pem,
                key_pem=encrypt_pem(key_pem),   # encrypted before hitting DB
                acme_status="issued",
                issued_at=func.now(),
                expires_at=expires_at,
            )
        )
        await conn.commit()


async def update_domain_acme_status(fqdn: str, status: str) -> None:
    async with get_conn() as conn:
        await conn.execute(
            update(domains_table)
            .where(domains_table.c.fqdn == fqdn)
            .values(acme_status=status)
        )
        await conn.commit()


# ── Audit Log ──────────────────────────────────────────────────────────────


async def write_audit_log(
    actor: str,
    action: str,
    resource: str | None = None,
    detail: dict | None = None,
) -> None:
    """
    Write one audit log entry. Called on every mutating API action.

    Parameters
    ----------
    actor    : IP address (or "system") of whoever triggered the action
    action   : dot-notation string, e.g. "settings.update", "domain.add"
    resource : the specific key/fqdn/worker_id being changed (for quick search)
    detail   : any additional context — e.g. {"old": "0.7", "new": "0.5"}

    Why we don't raise on failure: an audit write failure must never block
    the actual API response. We log the error and continue.
    """
    try:
        async with get_conn() as conn:
            await conn.execute(
                insert(audit_log_table).values(
                    actor=actor,
                    action=action,
                    resource=resource,
                    detail=detail or {},
                )
            )
            await conn.commit()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            "Failed to write audit log (action=%s): %s", action, e
        )


async def get_audit_log(limit: int = 100, offset: int = 0) -> list:
    async with get_conn() as conn:
        result = await conn.execute(
            select(audit_log_table)
            .order_by(desc(audit_log_table.c.created_at))
            .limit(limit)
            .offset(offset)
        )
        return result.mappings().all()
