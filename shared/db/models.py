from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

metadata = MetaData()

incidents = Table(
    "incidents",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("request_id", UUID(as_uuid=True), nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("method", Text, nullable=False),
    Column("path", Text, nullable=False),
    Column("source_ip", INET, nullable=True),
    Column("user_agent", Text, nullable=True),
    Column("guard_score", Float, nullable=False),
    Column("is_attack", Boolean, nullable=True),
    Column("attack_type", Text, nullable=True),
    Column("confidence", Float, nullable=True),
    Column("explanation", Text, nullable=True),
    Column("affected_parameter", Text, nullable=True),
    Column("remediation_hint", Text, nullable=True),
    Column("action_taken", Text, nullable=False, server_default="pass"),
    Column("pr_url", Text, nullable=True),
    Column("raw_request", JSONB, nullable=True),
    Column("worker_id", Text, nullable=True),
)

settings_table = Table(
    "settings",
    metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text, nullable=False),
    Column("description", Text, nullable=True),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    ),
)

workers_table = Table(
    "workers",
    metadata,
    Column("id", Text, primary_key=True),
    Column("host", Text, nullable=False),
    Column("port", Integer, nullable=False),
    Column("registered_at", DateTime(timezone=True), server_default=func.now()),
    Column("last_seen", DateTime(timezone=True), server_default=func.now()),
    Column("status", Text, server_default="healthy"),
)

domains_table = Table(
    "domains",
    metadata,
    Column("fqdn", Text, primary_key=True),
    Column("upstream_url", Text, nullable=False),
    Column("cert_pem", Text, nullable=True),
    Column("key_pem", Text, nullable=True),  # store encrypted
    Column("acme_status", Text, server_default="pending"),
    Column("issued_at", DateTime(timezone=True), nullable=True),
    Column("expires_at", DateTime(timezone=True), nullable=True),
)

stats_cache_table = Table(
    "stats_cache",
    metadata,
    Column("metric", Text, primary_key=True),
    Column("value", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now()),
)
