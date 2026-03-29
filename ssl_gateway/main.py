"""
CogniThorn SSL Gateway
- Port 80: HTTP (ACME HTTP-01 challenge responses + redirect to HTTPS)
- Port 443: HTTPS (SNI-aware TLS termination + worker routing)
"""
import asyncio
import logging
import ssl
import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route
import uvicorn

from ssl_gateway.acme_client import get_pending_challenge
from ssl_gateway.cert_store import restore_certs_from_db
from ssl_gateway.renewal_task import run_renewal_loop
from ssl_gateway.sni_router import get_context, build_sni_callback
from ssl_gateway.worker_router import forward_to_worker
from shared.db.database import run_migrations
from shared.redis_client import get_redis

logger = logging.getLogger(__name__)


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


# ── Startup ───────────────────────────────────────────────────────────────

async def startup():
    await run_migrations()
    await restore_certs_from_db()
    asyncio.create_task(run_renewal_loop())
    logger.info("SSL Gateway started")


http_app.add_event_handler("startup", startup)


# ── Entry point ───────────────────────────────────────────────────────────

async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Build a default self-signed SSL context for domains without certs yet
    default_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # We use SNI callback to switch to the real cert when available
    default_ssl_ctx.sni_callback = build_sni_callback(default_ssl_ctx)

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
        ssl_certfile=None,  # handled via SNI callback
        log_level="info",
    )

    server_http = uvicorn.Server(config_http)
    server_https = uvicorn.Server(config_https)

    await asyncio.gather(
        server_http.serve(),
        server_https.serve(),
    )


if __name__ == "__main__":
    asyncio.run(main())
