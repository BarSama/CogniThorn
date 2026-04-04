"""
Tests for ssl_gateway/worker_router.py — the L7 load balancer.

--- What we're testing ---
1. get_workers() filters to only healthy workers from the Redis hash
2. select_worker() does round-robin selection via Redis INCR
3. forward_to_worker() returns 503 when no workers are registered
4. forward_to_worker() succeeds when the first worker responds 200
5. forward_to_worker() retries the next worker if the first returns 502
6. forward_to_worker() returns 503 when ALL workers are unavailable
7. _mark_worker_failed() updates the worker's status to "unhealthy" in Redis

--- Why this matters ---
The worker router is the L7 load balancer. It runs on every single HTTPS
request. If it has a bug — e.g. doesn't retry on 502, or doesn't filter
unhealthy workers — traffic either gets stuck or sent to broken workers.
These tests verify the retry loop and Redis status updates work correctly.

--- How we test httpx calls ---
forward_to_worker() creates a fresh httpx.AsyncClient on each call. We
patch httpx.AsyncClient as a context manager mock so we can control what
status code the "worker" returns without a real HTTP server.
"""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.requests import Request
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import PlainTextResponse


# ── Helpers ───────────────────────────────────────────────────────────────────

def _worker(wid: str, host: str = "worker-host", port: int = 9000,
            status: str = "healthy") -> dict:
    """Build a worker dict matching the Redis hash format."""
    return {"id": wid, "host": host, "port": port, "status": status}


def _make_starlette_request(path: str = "/api/test", method: str = "GET") -> Request:
    """
    Build a minimal Starlette Request object for tests.

    Starlette's Request needs an ASGI scope dict. We provide the minimum
    required fields so worker_router can read .url.path, .method, etc.
    """
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [],
        "server": ("testserver", 80),
    }
    return Request(scope)


def _mock_httpx_client(status_code: int, content: bytes = b"ok"):
    """
    Return a mock httpx.AsyncClient context manager that returns a response
    with the given status code.

    Usage: patch("httpx.AsyncClient", return_value=_mock_httpx_client(200))
    """
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.content = content
    mock_resp.headers = {"content-type": "text/plain"}

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


# ── Test 1: get_workers filters to healthy only ───────────────────────────────

@pytest.mark.asyncio
async def test_get_workers_filters_healthy(mock_redis):
    """
    Given: Redis hash has 3 workers — 2 healthy, 1 unhealthy
    When:  get_workers() is called
    Then:  only the 2 healthy workers are returned

    Sending requests to unhealthy workers causes unnecessary errors and
    delays. The round-robin must skip known-bad workers.
    """
    from ssl_gateway.worker_router import get_workers

    workers = {
        "w1": json.dumps(_worker("w1", status="healthy")),
        "w2": json.dumps(_worker("w2", status="unhealthy")),
        "w3": json.dumps(_worker("w3", status="healthy")),
    }
    mock_redis.hgetall.return_value = workers

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        result = await get_workers()

    assert len(result) == 2
    ids = {w["id"] for w in result}
    assert ids == {"w1", "w3"}
    assert "w2" not in ids


# ── Test 2: get_workers returns empty list when Redis is empty ────────────────

@pytest.mark.asyncio
async def test_get_workers_empty_registry(mock_redis):
    """
    Given: Redis hash is empty (no workers registered)
    When:  get_workers() is called
    Then:  an empty list is returned (not an exception)

    This happens at startup before workers have registered. The router
    must handle it gracefully and return 503.
    """
    from ssl_gateway.worker_router import get_workers

    mock_redis.hgetall.return_value = {}

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        result = await get_workers()

    assert result == []


# ── Test 3: select_worker round-robins via Redis INCR ─────────────────────────

@pytest.mark.asyncio
async def test_select_worker_round_robin(mock_redis):
    """
    Given: 3 healthy workers and a Redis counter
    When:  select_worker() is called 4 times with INCR returning 1, 2, 3, 4
    Then:  workers cycle: w[1%3]=1, w[2%3]=2, w[3%3]=0, w[4%3]=1

    The round-robin is stateless from the caller's perspective — all state
    lives in `cognithhorn:lb:counter` in Redis. This is what enables
    multiple SSL Gateway replicas to share load correctly.
    """
    from ssl_gateway.worker_router import select_worker

    workers = [_worker("w0"), _worker("w1"), _worker("w2")]

    # INCR returns 1, 2, 3, 4 on successive calls
    mock_redis.incr.side_effect = [1, 2, 3, 4]

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        r1 = await select_worker(workers)
        r2 = await select_worker(workers)
        r3 = await select_worker(workers)
        r4 = await select_worker(workers)

    assert r1["id"] == "w1"   # 1 % 3 = 1
    assert r2["id"] == "w2"   # 2 % 3 = 2
    assert r3["id"] == "w0"   # 3 % 3 = 0
    assert r4["id"] == "w1"   # 4 % 3 = 1


# ── Test 4: select_worker returns None for empty list ─────────────────────────

@pytest.mark.asyncio
async def test_select_worker_empty_list(mock_redis):
    """
    Given: no healthy workers
    When:  select_worker([]) is called
    Then:  None is returned — caller must handle this case
    """
    from ssl_gateway.worker_router import select_worker

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        result = await select_worker([])

    assert result is None


# ── Test 5: forward_to_worker returns 503 when no workers ────────────────────

@pytest.mark.asyncio
async def test_forward_503_when_no_workers(mock_redis):
    """
    Given: Redis worker registry is empty
    When:  a request arrives at forward_to_worker()
    Then:  HTTP 503 is returned immediately — no attempt to forward

    503 is the correct HTTP status for "service unavailable". This protects
    the upstream from receiving requests when the WAF has no workers running.
    """
    from ssl_gateway.worker_router import forward_to_worker

    mock_redis.hgetall.return_value = {}

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        req = _make_starlette_request()
        resp = await forward_to_worker(req, b"", "http://upstream:3000")

    assert resp.status_code == 503


# ── Test 6: forward_to_worker succeeds on first healthy worker ────────────────

@pytest.mark.asyncio
async def test_forward_succeeds_on_healthy_worker(mock_redis):
    """
    Given: one healthy worker that returns HTTP 200
    When:  a request is forwarded
    Then:  the 200 response is returned to the caller
    """
    from ssl_gateway.worker_router import forward_to_worker

    workers = {"w1": json.dumps(_worker("w1", host="worker1", port=9000))}
    mock_redis.hgetall.return_value = workers
    mock_redis.incr.return_value = 1

    mock_client = _mock_httpx_client(200, b'{"ok": true}')

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("httpx.AsyncClient", return_value=mock_client):
            req = _make_starlette_request()
            resp = await forward_to_worker(req, b"", "http://upstream:3000")

    assert resp.status_code == 200


# ── Test 7: forward_to_worker retries on 502 ─────────────────────────────────

@pytest.mark.asyncio
async def test_forward_retries_on_502(mock_redis):
    """
    Given: 2 healthy workers — first returns 502, second returns 200
    When:  a request is forwarded
    Then:  the router retries with the second worker and returns 200

    502 = "Bad Gateway" — the worker itself is up but had an internal error
    (e.g. the upstream app it proxies to is down). We retry to give the
    second worker a chance.

    Why this resilience matters: under rolling deployments or partial
    crashes, some workers may be temporarily broken. The retry means
    users don't see errors during these windows.
    """
    from ssl_gateway.worker_router import forward_to_worker

    workers = {
        "w1": json.dumps(_worker("w1", host="worker1", port=9000)),
        "w2": json.dumps(_worker("w2", host="worker2", port=9000)),
    }
    mock_redis.hgetall.return_value = workers
    mock_redis.incr.return_value = 0  # select w1 first

    # w1 returns 502, w2 returns 200
    mock_client_502 = _mock_httpx_client(502)
    mock_client_200 = _mock_httpx_client(200, b"ok")

    # Mock _mark_worker_failed to avoid extra Redis calls
    call_count = 0

    def client_factory(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return mock_client_502 if call_count == 1 else mock_client_200

    mock_redis.hget.return_value = json.dumps(_worker("w1", status="healthy"))
    mock_redis.hset = AsyncMock()

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("httpx.AsyncClient", side_effect=client_factory):
            req = _make_starlette_request()
            resp = await forward_to_worker(req, b"", "http://upstream:3000")

    assert resp.status_code == 200


# ── Test 8: forward_to_worker returns 503 when all workers fail ───────────────

@pytest.mark.asyncio
async def test_forward_503_when_all_workers_fail(mock_redis):
    """
    Given: 2 workers, both return 503
    When:  forward_to_worker() tries them all
    Then:  HTTP 503 is returned to the caller

    This is the worst case: the entire WAF fleet is down. The SSL Gateway
    returns 503 rather than hanging indefinitely.
    """
    from ssl_gateway.worker_router import forward_to_worker

    workers = {
        "w1": json.dumps(_worker("w1", host="worker1", port=9000)),
        "w2": json.dumps(_worker("w2", host="worker2", port=9000)),
    }
    mock_redis.hgetall.return_value = workers
    mock_redis.incr.return_value = 0
    mock_redis.hget.return_value = None  # for _mark_worker_failed

    mock_client_503 = _mock_httpx_client(503)

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("httpx.AsyncClient", return_value=mock_client_503):
            req = _make_starlette_request()
            resp = await forward_to_worker(req, b"", "http://upstream:3000")

    assert resp.status_code == 503


# ── Test 9: forward_to_worker retries on connection error ────────────────────

@pytest.mark.asyncio
async def test_forward_retries_on_connection_error(mock_redis):
    """
    Given: first worker is unreachable (raises ConnectError), second is fine
    When:  forward_to_worker() is called
    Then:  it falls through to the second worker and returns 200

    Connection errors happen when the worker process has crashed entirely
    (vs 502 which means the process is up but the upstream is down).
    Both error types should trigger the same retry logic.
    """
    import httpx as httpx_module
    from ssl_gateway.worker_router import forward_to_worker

    workers = {
        "w1": json.dumps(_worker("w1", host="dead-worker", port=9000)),
        "w2": json.dumps(_worker("w2", host="live-worker", port=9000)),
    }
    mock_redis.hgetall.return_value = workers
    mock_redis.incr.return_value = 0
    mock_redis.hget.return_value = None

    call_count = 0
    mock_client_ok = _mock_httpx_client(200, b"ok")

    def client_factory(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First client raises on request()
            failing = AsyncMock()
            failing.request = AsyncMock(
                side_effect=httpx_module.ConnectError("Connection refused")
            )
            failing.__aenter__ = AsyncMock(return_value=failing)
            failing.__aexit__ = AsyncMock(return_value=False)
            return failing
        return mock_client_ok

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("httpx.AsyncClient", side_effect=client_factory):
            req = _make_starlette_request()
            resp = await forward_to_worker(req, b"", "http://upstream:3000")

    assert resp.status_code == 200


# ── Test 10: _mark_worker_failed sets status to unhealthy ─────────────────────

@pytest.mark.asyncio
async def test_mark_worker_failed_sets_unhealthy(mock_redis):
    """
    Given: a worker entry in the Redis hash with status="healthy"
    When:  _mark_worker_failed("w1") is called
    Then:  the worker's status is updated to "unhealthy" in Redis

    This is how the SSL Gateway does soft health-marking. The control
    plane's health_checker.py will eventually restore it to "healthy"
    when the worker recovers. But in the meantime, the LB skips it.
    """
    from ssl_gateway.worker_router import _mark_worker_failed

    initial_data = json.dumps(_worker("w1", status="healthy"))
    mock_redis.hget.return_value = initial_data

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        await _mark_worker_failed("w1")

    # Verify hset was called with the updated worker data
    mock_redis.hset.assert_called_once()
    hset_args = mock_redis.hset.call_args[0]
    assert hset_args[0] == "cognithhorn:workers"
    assert hset_args[1] == "w1"
    updated = json.loads(hset_args[2])
    assert updated["status"] == "unhealthy"


# ── Test 11: X-CogniThorn-Upstream header is injected ───────────────────────

@pytest.mark.asyncio
async def test_upstream_header_injected(mock_redis):
    """
    Given: upstream_url = "http://myapp:3000"
    When:  forward_to_worker() sends the request to a worker
    Then:  the X-CogniThorn-Upstream header is set in the forwarded request

    This is the multi-tenant routing mechanism. The WAF worker reads this
    header to know where to forward clean traffic after inspection. Without
    it, all domains would proxy to the same default upstream.
    """
    from ssl_gateway.worker_router import forward_to_worker

    workers = {"w1": json.dumps(_worker("w1", host="worker1", port=9000))}
    mock_redis.hgetall.return_value = workers
    mock_redis.incr.return_value = 1

    captured_headers = {}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"ok"
    mock_resp.headers = {}

    async def capture_request(method, url, headers, content):
        captured_headers.update(headers)
        return mock_resp

    mock_client = AsyncMock()
    mock_client.request = capture_request
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("httpx.AsyncClient", return_value=mock_client):
            req = _make_starlette_request()
            await forward_to_worker(req, b"", "http://myapp:3000")

    assert captured_headers.get("X-CogniThorn-Upstream") == "http://myapp:3000"
