"""
Encryption helpers for TLS private keys stored in PostgreSQL.

--- Why we need this ---
TLS private keys are stored in the `domains` table so the SSL Gateway can
serve the correct certificate per domain. Storing them as plaintext means
anyone who can read the DB (a leaked backup, a compromised container) has
your private keys — and can impersonate your domains.

--- How Fernet works ---
Fernet is a symmetric encryption scheme from the `cryptography` library.
It uses AES-128-CBC with PKCS7 padding + HMAC-SHA256 for authentication.
You give it a 32-byte URL-safe base64 key, and it gives back an opaque
encrypted token. The same key encrypts and decrypts — it must stay secret.

--- The ENC: prefix ---
We prefix all ciphertext with "ENC:" so we can tell encrypted values from
any plaintext rows that existed before encryption was turned on. This makes
the migration story safe: read a row, if it starts with "ENC:" decrypt it,
otherwise treat it as plaintext (and re-encrypt on next write).

--- Key derivation ---
The key comes from KEY_ENCRYPTION_SECRET env var. Fernet requires exactly
32 bytes encoded as URL-safe base64. Generate one with:
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
import base64
import logging

logger = logging.getLogger(__name__)

_FERNET_PREFIX = "ENC:"


def _get_fernet():
    """
    Lazily build a Fernet instance from settings.

    We import settings here (not at module level) to avoid circular imports —
    shared.crypto is imported by shared.db.crud which is imported by everything.
    """
    from shared.config.settings import settings

    secret = settings.key_encryption_secret
    if not secret:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(secret.encode())
    except Exception as e:
        logger.error("Invalid KEY_ENCRYPTION_SECRET — cannot encrypt keys: %s", e)
        return None


def encrypt_pem(plaintext: str | None) -> str | None:
    """
    Encrypt a PEM string before storing in the DB.
    Returns "ENC:<ciphertext>" or the original string if encryption is unavailable.
    """
    if plaintext is None:
        return None
    fernet = _get_fernet()
    if fernet is None:
        logger.warning(
            "KEY_ENCRYPTION_SECRET not set — storing key_pem as plaintext. "
            "Set this env var before going to production."
        )
        return plaintext
    token = fernet.encrypt(plaintext.encode()).decode()
    return f"{_FERNET_PREFIX}{token}"


def decrypt_pem(stored: str | None) -> str | None:
    """
    Decrypt a PEM string retrieved from the DB.
    Handles both encrypted ("ENC:...") and legacy plaintext values transparently.
    """
    if stored is None:
        return None
    if not stored.startswith(_FERNET_PREFIX):
        # Legacy plaintext row — return as-is; will be encrypted on next write
        return stored
    fernet = _get_fernet()
    if fernet is None:
        logger.error(
            "Cannot decrypt key_pem — KEY_ENCRYPTION_SECRET is missing. "
            "The SSL Gateway cannot serve this domain's certificate."
        )
        return None
    try:
        ciphertext = stored[len(_FERNET_PREFIX):]
        return fernet.decrypt(ciphertext.encode()).decode()
    except Exception as e:
        logger.error("Failed to decrypt key_pem: %s", e)
        return None
