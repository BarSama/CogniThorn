"""Parse a Starlette Request into a RequestContext dataclass."""
import uuid
import logging
from starlette.requests import Request
from shared.schemas import RequestContext
from shared.config.settings import settings

logger = logging.getLogger(__name__)


async def parse_request(request: Request, body: bytes) -> RequestContext:
    max_bytes = settings.max_body_size_kb * 1024
    body_str = ""
    if body:
        try:
            body_str = body[:max_bytes].decode("utf-8", errors="replace")
        except Exception:
            body_str = "<binary body>"

    upstream_url = request.headers.get("X-CogniThorn-Upstream") or settings.upstream_url

    return RequestContext(
        request_id=str(uuid.uuid4()),
        method=request.method,
        path=request.url.path,
        query_string=str(request.url.query),
        headers={k: v for k, v in request.headers.items()
                 if k.lower() not in {"authorization", "cookie", "x-cognithhorn-upstream"}},
        body=body_str,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        upstream_url=upstream_url,
    )
