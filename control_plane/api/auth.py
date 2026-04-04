"""
API key authentication for the CogniThorn control plane.

--- Why middleware instead of Depends() ---
FastAPI's Depends() system requires annotating every individual route
function. That's fragile — if someone adds a new route and forgets
to add the dependency, that route is silently public. A Starlette
middleware runs unconditionally on every request, so new routes are
automatically protected.

--- How it works ---
1. Every request to /api/* must include the header: X-API-Key: <secret>
2. The secret is set via CONTROL_PLANE_API_KEY env var
3. If the env var is empty (dev mode), auth is skipped but a warning is logged
4. /health is always exempt — load balancers and Docker healthchecks need it

--- Why X-API-Key instead of Bearer token ---
Bearer tokens (JWTs) carry expiry and claims, but require a signing key
and validation logic. For a single-admin tool like CogniThorn, a static
API key is simpler and just as secure — the dashboard is the only client.
Phase 2 extension: add per-user JWTs if multi-user access is needed.
"""
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths that are always public — no key needed
_EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Reject any /api/* request that doesn't carry the correct X-API-Key header.
    """

    async def dispatch(self, request: Request, call_next):
        # Only guard /api/ routes
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        # Exempt paths (health, docs) — even if they happen to start with /api/
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        from shared.config.settings import settings
        api_key = settings.control_plane_api_key

        if not api_key:
            # Dev mode: no key configured — warn but allow
            logger.warning(
                "CONTROL_PLANE_API_KEY is not set. "
                "All /api/* routes are unauthenticated. "
                "Set this env var before exposing the control plane."
            )
            return await call_next(request)

        provided = request.headers.get("X-API-Key", "")
        if provided != api_key:
            logger.warning(
                "Rejected API request to %s — invalid or missing X-API-Key "
                "(caller: %s)",
                request.url.path,
                request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Missing or invalid X-API-Key header.",
                },
            )

        return await call_next(request)
