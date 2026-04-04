"""
Tests for data_plane/proxy/middleware.py — the core WAF dispatch logic.

--- What we're testing ---
1. Low guard score → request forwarded to upstream (clean traffic path)
2. High guard score + Gemini says false positive → forwarded (not blocked)
3. High guard score + Gemini confirms attack → 403 response returned
4. The 403 JSON body contains the right fields (blocked, attack_type, explanation)
5. Clean traffic NEVER writes to PostgreSQL (only Redis counters)
6. Blocked traffic writes to PostgreSQL AND increments Redis counters

--- How the test app works ---
We create a minimal FastAPI app with WAFMiddleware attached, then use
httpx.AsyncClient(app=app) to send requests directly in-process —
no real HTTP server is needed. This is called an "ASGI test client".

--- Why we mock guard, analyst, and forwarder ---
The middleware orchestrates those three components. We want to test the
orchestration logic (the "traffic cop") independently of each component.
If we let real ONNX inference run in the middleware test, a test failure
could mean either "the middleware logic is wrong" OR "the model is wrong" —
we couldn't tell which. Mocking isolates the variable.
"""
import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI
from unittest.mock import AsyncMock, MagicMock, patch

from shared.schemas import GuardResult, Verdict


# ── Test app factory ──────────────────────────────────────────────────────────

def make_test_app():
    """Create a FastAPI app with WAFMiddleware for testing."""
    from data_plane.proxy.middleware import WAFMiddleware
    app = FastAPI()
    app.add_middleware(WAFMiddleware)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


# ── Shared patches applied to every test in this module ──────────────────────
# We patch at the module level so tests don't need to repeat boilerplate.

PASS_RESULT = GuardResult(score=0.2, passed=True)   # clean traffic
BLOCK_RESULT = GuardResult(score=0.85, passed=False)  # suspicious traffic

ATTACK_VERDICT = Verdict(
    is_attack=True,
    attack_type="sqli",
    confidence=0.97,
    explanation="SQL injection via OR-based bypass in 'username' field.",
    affected_parameter="username",
    remediation_hint="Use parameterized queries.",
)
FP_VERDICT = Verdict(
    is_attack=False,
    attack_type="none",
    confidence=0.82,
    explanation="Legitimate request despite unusual syntax.",
)

UPSTREAM_RESPONSE = httpx.Response(200, json={"user": "alice"})


# ── Test 1: Clean traffic is forwarded ───────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_request_is_forwarded():
    """
    Given: guard scores the request as clean (score=0.2, passed=True)
    When:  the request hits the WAF
    Then:  it is forwarded to upstream and the upstream response returned
           Gemini is NEVER called (no reason to — guard passed it)
           PostgreSQL is NEVER written (only Redis counter is incremented)
    """
    app = make_test_app()

    with patch("data_plane.detection.guard.score", new_callable=AsyncMock, return_value=PASS_RESULT):
        with patch("data_plane.detection.analyst.analyze", new_callable=AsyncMock) as mock_analyst:
            with patch("data_plane.proxy.forwarder.forward", new_callable=AsyncMock,
                       return_value=httpx.Response(200, json={"ok": True})):
                with patch("data_plane.worker.config_subscriber.get_threshold", return_value=0.7):
                    with patch("shared.redis_client.get_redis"):
                        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
                            resp = await client.get("/api/users")

    assert resp.status_code == 200
    mock_analyst.assert_not_called()  # Gemini never touched


# ── Test 2: False positive is forwarded ──────────────────────────────────────

@pytest.mark.asyncio
async def test_false_positive_is_forwarded():
    """
    Given: guard flags request as suspicious (score=0.85, passed=False)
    But:   Gemini says it's a false positive (is_attack=False)
    Then:  request is forwarded — we don't punish users for false positives
    """
    app = make_test_app()

    with patch("data_plane.detection.guard.score", new_callable=AsyncMock, return_value=BLOCK_RESULT):
        with patch("data_plane.detection.analyst.analyze", new_callable=AsyncMock, return_value=FP_VERDICT):
            with patch("data_plane.proxy.forwarder.forward", new_callable=AsyncMock,
                       return_value=httpx.Response(200, json={"ok": True})) as mock_fwd:
                with patch("data_plane.worker.config_subscriber.get_threshold", return_value=0.7):
                    with patch("shared.redis_client.get_redis"):
                        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
                            resp = await client.post("/login", data={"username": "test"})

    assert resp.status_code == 200
    mock_fwd.assert_called_once()  # upstream was called


# ── Test 3: Confirmed attack is blocked ──────────────────────────────────────

@pytest.mark.asyncio
async def test_confirmed_attack_returns_403():
    """
    Given: guard flags as suspicious AND Gemini confirms it's an attack
    When:  the request hits the WAF
    Then:  upstream is NEVER called, client receives 403
    """
    app = make_test_app()

    with patch("data_plane.detection.guard.score", new_callable=AsyncMock, return_value=BLOCK_RESULT):
        with patch("data_plane.detection.analyst.analyze", new_callable=AsyncMock, return_value=ATTACK_VERDICT):
            with patch("data_plane.proxy.forwarder.forward", new_callable=AsyncMock) as mock_fwd:
                with patch("data_plane.worker.config_subscriber.get_threshold", return_value=0.7):
                    with patch("shared.redis_client.get_redis"):
                        with patch("shared.db.crud.log_incident_blocked", new_callable=AsyncMock):
                            async with httpx.AsyncClient(app=app, base_url="http://test") as client:
                                resp = await client.post(
                                    "/login",
                                    data={"username": "admin' OR '1'='1'"},
                                )

    assert resp.status_code == 403
    mock_fwd.assert_not_called()  # upstream was never reached


# ── Test 4: 403 response has correct JSON shape ───────────────────────────────

@pytest.mark.asyncio
async def test_403_response_json_fields():
    """
    The 403 response must contain:
    - blocked: True
    - attack_type: the detected attack category
    - explanation: a human-readable sentence
    - request_id: the UUID for this request (so operators can correlate with logs)

    Why request_id matters: if a user reports "I got blocked and I shouldn't have",
    the operator needs the request_id to look up the incident in the dashboard.
    """
    app = make_test_app()

    with patch("data_plane.detection.guard.score", new_callable=AsyncMock, return_value=BLOCK_RESULT):
        with patch("data_plane.detection.analyst.analyze", new_callable=AsyncMock, return_value=ATTACK_VERDICT):
            with patch("data_plane.proxy.forwarder.forward", new_callable=AsyncMock):
                with patch("data_plane.worker.config_subscriber.get_threshold", return_value=0.7):
                    with patch("shared.redis_client.get_redis"):
                        with patch("shared.db.crud.log_incident_blocked", new_callable=AsyncMock):
                            async with httpx.AsyncClient(app=app, base_url="http://test") as client:
                                resp = await client.post("/login", data={"username": "evil"})

    body = resp.json()
    assert body["blocked"] is True
    assert body["attack_type"] == "sqli"
    assert "explanation" in body
    assert "request_id" in body
    assert len(body["request_id"]) > 0


# ── Test 5: Blocked traffic writes to DB; clean does not ─────────────────────

@pytest.mark.asyncio
async def test_blocked_traffic_writes_to_db():
    """
    The strict logging policy: only write to PostgreSQL for confirmed attacks.
    Clean traffic must only increment Redis counters — never touch the DB.

    Why: at 1000 req/s, storing every clean request would write ~86M rows/day.
    That's ~86GB/day if each row is 1KB. The DB would explode in hours.
    """
    app = make_test_app()
    mock_redis_instance = AsyncMock()
    mock_redis_instance.incr = AsyncMock(return_value=1)

    with patch("data_plane.detection.guard.score", new_callable=AsyncMock, return_value=BLOCK_RESULT):
        with patch("data_plane.detection.analyst.analyze", new_callable=AsyncMock, return_value=ATTACK_VERDICT):
            with patch("data_plane.proxy.forwarder.forward", new_callable=AsyncMock):
                with patch("data_plane.worker.config_subscriber.get_threshold", return_value=0.7):
                    with patch("shared.redis_client.get_redis", return_value=mock_redis_instance):
                        with patch("shared.db.crud.log_incident_blocked", new_callable=AsyncMock) as mock_db:
                            async with httpx.AsyncClient(app=app, base_url="http://test") as client:
                                await client.post("/login", data={"username": "evil"})
                            # Give background tasks time to complete
                            import asyncio
                            await asyncio.sleep(0.1)

    mock_db.assert_called_once()  # DB write happened for the blocked incident


@pytest.mark.asyncio
async def test_clean_traffic_does_not_write_to_db():
    """Clean traffic must ONLY increment Redis counters, never write to PostgreSQL."""
    app = make_test_app()
    mock_redis_instance = AsyncMock()
    mock_redis_instance.incr = AsyncMock(return_value=1)

    with patch("data_plane.detection.guard.score", new_callable=AsyncMock, return_value=PASS_RESULT):
        with patch("data_plane.detection.analyst.analyze", new_callable=AsyncMock) as mock_analyst:
            with patch("data_plane.proxy.forwarder.forward", new_callable=AsyncMock,
                       return_value=httpx.Response(200)):
                with patch("data_plane.worker.config_subscriber.get_threshold", return_value=0.7):
                    with patch("shared.redis_client.get_redis", return_value=mock_redis_instance):
                        with patch("shared.db.crud.log_incident_blocked", new_callable=AsyncMock) as mock_db:
                            async with httpx.AsyncClient(app=app, base_url="http://test") as client:
                                await client.get("/api/users")
                            import asyncio
                            await asyncio.sleep(0.1)

    mock_db.assert_not_called()  # DB was never touched
    mock_analyst.assert_not_called()  # Gemini was never called
