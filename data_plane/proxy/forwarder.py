"""Async HTTP forwarder using a module-level httpx.AsyncClient singleton."""
import logging
import httpx
from starlette.requests import Request
from starlette.responses import Response
from shared.schemas import RequestContext

logger = logging.getLogger(__name__)

_client: httpx.AsyncClient | None = None

EXCLUDED_HEADERS = {
    "host", "content-length", "transfer-encoding",
    "x-cognithhorn-upstream", "connection",
}


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
            follow_redirects=True,
        )
    return _client


async def forward(ctx: RequestContext, raw_body: bytes) -> Response:
    """Forward a request to the upstream and return the response."""
    upstream = ctx.upstream_url or "http://upstream:80"
    url = f"{upstream.rstrip('/')}{ctx.path}"
    if ctx.query_string:
        url = f"{url}?{ctx.query_string}"

    headers = {k: v for k, v in ctx.headers.items() if k.lower() not in EXCLUDED_HEADERS}
    headers["X-Forwarded-For"] = ctx.source_ip or "unknown"
    headers["X-Real-IP"] = ctx.source_ip or "unknown"

    try:
        resp = await get_client().request(
            method=ctx.method,
            url=url,
            headers=headers,
            content=raw_body,
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            media_type=resp.headers.get("content-type"),
        )
    except httpx.ConnectError as e:
        logger.error("Cannot connect to upstream %s: %s", upstream, e)
        return Response(content=b"Bad Gateway", status_code=502)
    except httpx.TimeoutException as e:
        logger.error("Upstream timeout: %s", e)
        return Response(content=b"Gateway Timeout", status_code=504)
