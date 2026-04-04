"""
Shared pytest fixtures for CogniThorn tests.

--- What is a fixture? ---
A fixture is a reusable setup function that pytest runs before each test.
Think of it like the "before each" in other testing frameworks.
We use fixtures so that every test starts with a clean, predictable state
rather than sharing state between tests (which causes flaky tests).

--- Why do we mock Redis and the DB here? ---
Our code calls Redis (for counters/config) and PostgreSQL (for incidents).
In tests we don't want:
  - A real Redis server running (flaky CI, network dependency)
  - A real PostgreSQL server (same reasons, plus data pollution between tests)
So we replace them with AsyncMock objects that behave like the real thing
but are controlled entirely by the test.
"""
import asyncio
import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# ── Event loop ────────────────────────────────────────────────────────────────
# pytest-asyncio needs an event loop for async tests.
# "session" scope means one loop is reused for all tests (faster).

@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Fake Redis ────────────────────────────────────────────────────────────────
# AsyncMock creates an object where every method returns a coroutine.
# This perfectly mimics redis.asyncio.Redis for our tests.

@pytest.fixture
def mock_redis():
    """A fake Redis client. Tests can configure .get.return_value etc."""
    r = AsyncMock()
    r.get.return_value = None          # cache miss by default
    r.set.return_value = True
    r.incr.return_value = 1
    r.hgetall.return_value = {}
    r.hget.return_value = None
    r.hset.return_value = True
    r.hdel.return_value = 1
    r.expire.return_value = True
    r.publish.return_value = 1
    # pubsub mock
    pubsub = AsyncMock()
    pubsub.subscribe = AsyncMock()
    pubsub.listen = AsyncMock(return_value=aiter([]))  # empty async iterator
    r.pubsub.return_value = pubsub
    return r


def aiter(items):
    """Helper: turn a list into an async iterator for mocking pubsub.listen."""
    async def _gen():
        for item in items:
            yield item
    return _gen()


# ── Fake DB connection ────────────────────────────────────────────────────────

@pytest.fixture
def mock_db_conn():
    """A fake async DB connection context manager."""
    conn = AsyncMock()
    conn.execute = AsyncMock()
    conn.commit = AsyncMock()

    # Make it work as an async context manager: `async with get_conn() as conn`
    cm = AsyncMock()
    cm.__aenter__.return_value = conn
    cm.__aexit__.return_value = False
    return cm, conn


# ── Sample requests ───────────────────────────────────────────────────────────
# Reusable RequestContext objects representing clean and malicious traffic.

@pytest.fixture
def clean_request():
    """A normal GET request — should score low and pass."""
    from shared.schemas import RequestContext
    return RequestContext(
        request_id="test-clean-001",
        method="GET",
        path="/api/users",
        query_string="page=1",
        headers={"user-agent": "Mozilla/5.0"},
        body="",
        source_ip="1.2.3.4",
        user_agent="Mozilla/5.0",
        upstream_url="http://upstream:3000",
    )


@pytest.fixture
def sqli_request():
    """A POST request with a classic SQL injection payload — should score high."""
    from shared.schemas import RequestContext
    return RequestContext(
        request_id="test-sqli-001",
        method="POST",
        path="/login",
        query_string="",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body="username=admin' OR '1'='1' --&password=x",
        source_ip="5.6.7.8",
        user_agent="curl/7.64.0",
        upstream_url="http://upstream:3000",
    )


@pytest.fixture
def xss_request():
    """A GET request with an XSS payload in the query string."""
    from shared.schemas import RequestContext
    return RequestContext(
        request_id="test-xss-001",
        method="GET",
        path="/search",
        query_string="q=<script>alert(document.cookie)</script>",
        headers={},
        body="",
        source_ip="9.10.11.12",
        user_agent="python-requests/2.28",
        upstream_url="http://upstream:3000",
    )


# ── Sample Verdicts ───────────────────────────────────────────────────────────

@pytest.fixture
def sqli_verdict():
    """A Gemini verdict confirming a SQL injection attack."""
    from shared.schemas import Verdict
    return Verdict(
        is_attack=True,
        attack_type="sqli",
        confidence=0.97,
        explanation="SQL injection attempt detected in the 'username' parameter using OR-based bypass.",
        affected_parameter="username",
        remediation_hint="Use parameterized queries or prepared statements.",
    )


@pytest.fixture
def false_positive_verdict():
    """A Gemini verdict saying the request is NOT actually an attack."""
    from shared.schemas import Verdict
    return Verdict(
        is_attack=False,
        attack_type="none",
        confidence=0.88,
        explanation="Request appears to be a legitimate query despite unusual syntax.",
    )
