"""
ACME HTTP-01 challenge client.
Issues and renews Let's Encrypt certificates using the `acme` library.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# In-memory store for pending ACME challenges: {token: key_authorization}
_pending_challenges: dict[str, str] = {}

ACME_DIRECTORY = os.getenv("ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory")
CONTACT_EMAIL = os.getenv("ACME_EMAIL", "admin@example.com")
ACCOUNT_KEY_PATH = Path(os.getenv("ACME_KEY_PATH", "/certs/account.key"))


def get_pending_challenge(token: str) -> str | None:
    return _pending_challenges.get(token)


async def issue_certificate(fqdn: str) -> tuple[str, str, datetime] | None:
    """
    Issue a certificate for fqdn via ACME HTTP-01 challenge.
    Returns (cert_pem, key_auth, expires_at) or None on failure.
    """
    try:
        return await asyncio.to_thread(_issue_sync, fqdn)
    except Exception as e:
        logger.error("ACME certificate issuance failed for %s: %s", fqdn, e, exc_info=True)
        return None


def _issue_sync(fqdn: str) -> tuple[str, str, datetime]:
    """Blocking ACME issuance (run in executor)."""
    import josepy as jose
    from acme import challenges, client, crypto_util, messages
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    import OpenSSL.crypto

    # --- Account key ---
    ACCOUNT_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if ACCOUNT_KEY_PATH.exists():
        account_key = jose.JWK.load(ACCOUNT_KEY_PATH.read_bytes())
    else:
        rsa_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        account_key = jose.JWKRSA(key=rsa_key)
        ACCOUNT_KEY_PATH.write_bytes(account_key.key.private_bytes(
            encoding=OpenSSL.crypto.FILETYPE_PEM,
            format=rsa.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=rsa.NoEncryption(),
        ))

    # --- ACME client ---
    net = client.ClientNetwork(account_key, user_agent="CogniThorn-WAF/0.1")
    directory = messages.Directory.from_json(
        net.get(ACME_DIRECTORY).json()
    )
    acme = client.ClientV2(directory, net)

    # --- Register / load account ---
    regr = acme.new_account(
        messages.NewRegistration.from_data(
            email=CONTACT_EMAIL, terms_of_service_agreed=True
        )
    )

    # --- Order ---
    order = acme.new_order(crypto_util.make_csr(fqdn.encode(), [fqdn]))

    # --- HTTP-01 challenge ---
    for auth in order.authorizations:
        for ch in auth.body.challenges:
            if isinstance(ch.chall, challenges.HTTP01):
                response, validation = ch.chall.response_and_validation(account_key)
                token = ch.chall.encode("token")
                _pending_challenges[token] = validation
                acme.answer_challenge(ch, response)
                _pending_challenges.pop(token, None)

    # --- Finalize ---
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    domain_key = _rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    csr = crypto_util.make_csr(fqdn.encode(), [fqdn])
    order = acme.poll_and_finalize(order)

    cert_pem = order.fullchain_pem
    key_pem = domain_key.private_bytes(
        encoding=OpenSSL.crypto.FILETYPE_PEM,
        format=_rsa.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=_rsa.NoEncryption(),
    ).decode()

    # Parse expiry from cert
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    expires_at = cert.not_valid_after_utc

    return cert_pem, key_pem, expires_at
