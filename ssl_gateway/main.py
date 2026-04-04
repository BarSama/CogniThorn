"""
CogniThorn SSL Gateway
- Port 80: HTTP (ACME HTTP-01 challenge responses + redirect to HTTPS)
- Port 443: HTTPS (SNI-aware TLS termination + worker routing)

Fix note: uvicorn.Config has no `ssl_context` parameter — it only accepts
ssl_certfile/ssl_keyfile paths and builds its own SSLContext internally.
To inject our SNI callback we:
  1. Generate a self-signed default cert on first boot (for domains not yet provisioned)
  2. Pass those paths to uvicorn so it can start TLS
  3. After config.load(), replace config.ssl with our custom SSLContext
     (which has the per-domain SNI callback wired in)
"""
import asyncio
import datetime
import logging
import os
import ssl

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route
import uvicorn

from ssl_gateway.acme_client import get_pending_challenge
from ssl_gateway.cert_store import restore_certs_from_db
from ssl_gateway.renewal_task import run_renewal_loop
from ssl_gateway.sni_router import build_sni_callback
from ssl_gateway.worker_router import forward_to_worker
from shared.db.database import run_migrations
from shared.redis_client import get_redis

logger = logging.getLogger(__name__)

DEFAULT_CERT_DIR = os.path.join(os.getenv("CERTS_DIR", "/certs"), "_default")
DEFAULT_CERT_FILE = os.path.join(DEFAULT_CERT_DIR, "fullchain.pem")
DEFAULT_KEY_FILE = os.path.join(DEFAULT_CERT_DIR, "privkey.pem")


# ── HTTP app (port 80) ────────────────────────────────────────────────────

async def acme_challenge(request: Request) -> Response:
    """Serve ACME HTTP-01 challenge token."""
    token = request.path_params["token"]
    key_auth = get_pending_challenge(token)
    if key_auth:
        return PlainTextResponse(key_auth)
    return Response(status_code=404)


async def http_redirect(request: Request) -> Response:
    """Redirect all non-ACME HTTP traffic to HTTPS."""
    host = request.headers.get("host", "").split(":")[0]
    url = f"https://{host}{request.url.path}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    return RedirectResponse(url=url, status_code=301)


http_app = Starlette(routes=[
    Route("/.well-known/acme-challenge/{token}", acme_challenge),
    Route("/{path:path}", http_redirect),
    Route("/", http_redirect),
])


# ── HTTPS app (port 443) ──────────────────────────────────────────────────

async def https_handler(request: Request) -> Response:
    """Route decrypted HTTPS traffic to a WAF worker."""
    host = request.headers.get("host", "").split(":")[0]

    # Get upstream URL for this domain from Redis
    try:
        redis = get_redis()
        domain_data = await redis.hgetall(f"cognithhorn:domain:{host}")
        upstream_url = domain_data.get("upstream_url", os.getenv("UPSTREAM_URL", "http://upstream:80"))
    except Exception:
        upstream_url = os.getenv("UPSTREAM_URL", "http://upstream:80")

    body = await request.body()
    return await forward_to_worker(request, body, upstream_url)


https_app = Starlette(routes=[
    Route("/{path:path}", https_handler, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]),
    Route("/", https_handler, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]),
])


# ── Default self-signed cert ──────────────────────────────────────────────

def _ensure_default_cert() -> None:
    """
    Generate a self-signed cert for the default SSLContext on first boot.

    Why we need this: uvicorn requires actual cert files to start TLS. This
    default cert is ONLY used for connections where we don't yet have a real
    Let's Encrypt cert (e.g. a domain was just added and ACME hasn't run yet).
    Browsers will show a warning for this cert — that's expected and intentional.
    Once ACME issues a real cert, the SNI callback switches to it automatically.
    """
    if os.path.exists(DEFAULT_CERT_FILE) and os.path.exists(DEFAULT_KEY_FILE):
        return

    os.makedirs(DEFAULT_CERT_DIR, exist_ok=True)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "cognithhorn-default"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(DEFAULT_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(DEFAULT_KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        os.chmod(DEFAULT_KEY_FILE, 0o600)
        logger.info("Generated default self-signed certificate at %s", DEFAULT_CERT_DIR)
    except Exception as e:
        logger.critical("Failed to generate default certificate: %s", e)
        raise


def _build_sni_ssl_context() -> ssl.SSLContext:
    """
    Build the SSLContext that uvicorn will actually use for port 443.

    Strategy:
      - Load the default self-signed cert into the context (uvicorn needs
        something to start TLS — it can't start with no cert at all)
      - Attach our SNI callback so that for any domain with a real Let's
        Encrypt cert, Python's TLS stack swaps in the correct SSLContext
        mid-handshake before the client ever sees the default cert
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=DEFAULT_CERT_FILE, keyfile=DEFAULT_KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Wire in the per-domain cert switcher
    ctx.sni_callback = build_sni_callback(ctx)
    return ctx


# ── Startup ───────────────────────────────────────────────────────────────

async def startup():
    await run_migrations()
    await restore_certs_from_db()
    asyncio.create_task(run_renewal_loop())
    logger.info("SSL Gateway started")


http_app.add_event_handler("startup", startup)


# ── Entry point ───────────────────────────────────────────────────────────

async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Step 1: ensure a default cert exists on disk (required by uvicorn to start TLS)
    _ensure_default_cert()

    # Step 2: build our custom SSLContext with the SNI callback
    sni_ctx = _build_sni_ssl_context()

    # Step 3: configure uvicorn with the default cert paths
    config_http = uvicorn.Config(
        http_app,
        host="0.0.0.0",
        port=80,
        log_level="info",
    )
    config_https = uvicorn.Config(
        https_app,
        host="0.0.0.0",
        port=443,
        ssl_certfile=DEFAULT_CERT_FILE,
        ssl_keyfile=DEFAULT_KEY_FILE,
        log_level="info",
    )

    # Step 4: load the uvicorn config (this builds its internal SSLContext
    # from the cert files we passed) then REPLACE it with our custom context
    # which has the SNI callback. This is the critical wiring step.
    config_https.load()
    config_https.ssl = sni_ctx
    logger.info("SNI callback wired into HTTPS server context")

    server_http = uvicorn.Server(config_http)
    server_https = uvicorn.Server(config_https)

    await asyncio.gather(
        server_http.serve(),
        server_https.serve(),
    )


if __name__ == "__main__":
    asyncio.run(main())
