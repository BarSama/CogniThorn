"""
Background task: check all domain certificates every 24 hours.
Renew any cert expiring within 30 days.
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from shared.db.crud import get_all_domains, update_domain_acme_status
from ssl_gateway.acme_client import issue_certificate
from ssl_gateway.cert_store import write_cert
from ssl_gateway.sni_router import reload_context

logger = logging.getLogger(__name__)

RENEW_BEFORE_DAYS = 30
CHECK_INTERVAL_HOURS = 24


async def run_renewal_loop() -> None:
    """Run forever, checking cert expiry once per day."""
    while True:
        try:
            await _check_and_renew_all()
        except Exception as e:
            logger.error("Renewal loop error: %s", e)
        await asyncio.sleep(CHECK_INTERVAL_HOURS * 3600)


async def _check_and_renew_all() -> None:
    domains = await get_all_domains()
    now = datetime.now(tz=timezone.utc)
    for row in domains:
        fqdn = row["fqdn"]
        acme_status = row.get("acme_status", "pending")

        # Issue cert for newly added domains
        if acme_status in ("pending", "failed"):
            await _issue_for_domain(fqdn)
            continue

        # Renew if expiring soon
        expires_at = row.get("expires_at")
        if expires_at and (expires_at - now) < timedelta(days=RENEW_BEFORE_DAYS):
            logger.info("Certificate for %s expires %s — renewing", fqdn, expires_at)
            await _issue_for_domain(fqdn)


async def _issue_for_domain(fqdn: str) -> None:
    await update_domain_acme_status(fqdn, "issuing")
    result = await issue_certificate(fqdn)
    if result:
        cert_pem, key_pem, expires_at = result
        await write_cert(fqdn, cert_pem, key_pem, expires_at)
        reload_context(fqdn)
        logger.info("Certificate issued/renewed for %s", fqdn)
    else:
        await update_domain_acme_status(fqdn, "failed")
        logger.error("Certificate issuance failed for %s", fqdn)
