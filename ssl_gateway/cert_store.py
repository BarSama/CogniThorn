"""
Load and store TLS certificates.
Certs are written to /certs/{fqdn}/ on disk and mirrored to PostgreSQL.
"""
import asyncio
import logging
import os
import ssl
from datetime import datetime
from pathlib import Path

from shared.config.settings import settings
from shared.db.crud import get_all_domains, update_domain_cert, get_domain

logger = logging.getLogger(__name__)


def cert_dir(fqdn: str) -> Path:
    return Path(settings.certs_dir) / fqdn


def cert_path(fqdn: str) -> Path:
    return cert_dir(fqdn) / "fullchain.pem"


def key_path(fqdn: str) -> Path:
    return cert_dir(fqdn) / "privkey.pem"


def has_cert(fqdn: str) -> bool:
    return cert_path(fqdn).exists() and key_path(fqdn).exists()


def load_ssl_context(fqdn: str) -> ssl.SSLContext:
    """Create an SSLContext for a given domain."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path(fqdn)), keyfile=str(key_path(fqdn)))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


async def write_cert(fqdn: str, cert_pem: str, key_pem: str, expires_at: datetime) -> None:
    """Write cert to disk and update PostgreSQL."""
    d = cert_dir(fqdn)
    await asyncio.to_thread(_write_cert_sync, d, cert_pem, key_pem)
    await update_domain_cert(fqdn, cert_pem, key_pem, expires_at)
    logger.info("Certificate stored for %s (expires %s)", fqdn, expires_at)


def _write_cert_sync(d: Path, cert_pem: str, key_pem: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "fullchain.pem").write_text(cert_pem)
    (d / "privkey.pem").write_text(key_pem)
    os.chmod(d / "privkey.pem", 0o600)


async def restore_certs_from_db() -> None:
    """On startup: restore any certs stored in DB to disk (e.g. after container restart)."""
    domains = await get_all_domains()
    for row in domains:
        fqdn = row["fqdn"]
        if row.get("cert_pem") and row.get("key_pem") and not has_cert(fqdn):
            d = cert_dir(fqdn)
            await asyncio.to_thread(_write_cert_sync, d, row["cert_pem"], row["key_pem"])
            logger.info("Restored cert for %s from database", fqdn)
