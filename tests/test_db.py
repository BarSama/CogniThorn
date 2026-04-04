"""
Tests for shared/db/crud.py — the database access layer.

--- What we're testing ---
1. log_incident_blocked() calls conn.execute() and conn.commit() — writes to DB
2. log_incident_blocked() passes the correct values (request_id, attack_type, etc.)
3. get_incidents() executes a SELECT and returns mapped rows
4. get_setting() returns value when key exists, None when it doesn't
5. upsert_setting() calls conn.execute() and conn.commit()

--- Why we mock get_conn ---
get_conn() opens a real asyncpg connection to PostgreSQL. In tests we have
no DB running. We mock it as an async context manager so the `async with`
syntax works, and we capture the execute()/commit() calls to verify behavior.

--- The critical design rule this enforces ---
Clean traffic NEVER calls log_incident_blocked() — it only increments Redis
counters via the middleware's _increment_counters() helper. This test suite
ensures the DB layer itself works correctly; test_proxy.py verifies that
the middleware only invokes it when appropriate.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from datetime import datetime

from shared.schemas import IncidentCreate, WorkerInfo


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_conn_cm(conn: AsyncMock):
    """
    Wrap a mock connection so it works as `async with get_conn() as conn`.

    get_conn() returns an async context manager. When you write:
        async with get_conn() as conn:
            ...
    Python calls __aenter__() to get `conn`, then __aexit__() to close it.
    We wire up both so our mock behaves like the real thing.
    """
    cm = AsyncMock()
    cm.__aenter__.return_value = conn
    cm.__aexit__.return_value = False
    return cm


def _make_incident() -> IncidentCreate:
    """Build a minimal IncidentCreate for testing."""
    return IncidentCreate(
        request_id="test-req-001",
        method="POST",
        path="/login",
        source_ip="1.2.3.4",
        user_agent="curl/7.0",
        guard_score=0.92,
        is_attack=True,
        attack_type="sqli",
        confidence=0.97,
        explanation="SQL injection via OR-based bypass.",
        affected_parameter="username",
        remediation_hint="Use parameterized queries.",
        action_taken="block",
        worker_id="worker-1",
        raw_request={"method": "POST", "path": "/login", "body": "username=evil"},
    )


# ── Test 1: log_incident_blocked writes to DB ─────────────────────────────────

@pytest.mark.asyncio
async def test_log_incident_blocked_executes_insert():
    """
    Given: a confirmed attack incident
    When:  log_incident_blocked() is called
    Then:  conn.execute() is called once (the INSERT) and conn.commit() is called

    This verifies the DB write path is actually triggered and not silently
    swallowed. If execute() is never called, the incident is lost forever.
    """
    from shared.db.crud import log_incident_blocked

    conn = AsyncMock()
    conn.execute = AsyncMock()
    conn.commit = AsyncMock()

    with patch("shared.db.crud.get_conn", return_value=_make_conn_cm(conn)):
        await log_incident_blocked(_make_incident())

    conn.execute.assert_called_once()
    conn.commit.assert_called_once()


# ── Test 2: log_incident_blocked passes the correct fields ────────────────────

@pytest.mark.asyncio
async def test_log_incident_blocked_passes_correct_values():
    """
    Given: an incident with specific fields
    When:  log_incident_blocked() is called
    Then:  the INSERT statement is built with the correct column values

    Why this matters: a silent off-by-one in the VALUES clause could mean
    the attack_type gets stored in the path column, or the explanation is
    lost. We capture the INSERT call args to verify mapping.
    """
    from shared.db.crud import log_incident_blocked
    from shared.db.models import incidents
    from sqlalchemy import insert

    inc = _make_incident()
    conn = AsyncMock()
    conn.execute = AsyncMock()
    conn.commit = AsyncMock()

    with patch("shared.db.crud.get_conn", return_value=_make_conn_cm(conn)):
        await log_incident_blocked(inc)

    # Capture the SQLAlchemy Insert object passed to execute()
    call_args = conn.execute.call_args[0][0]  # first positional arg
    # Verify the compiled values contain our data
    compiled_params = call_args.compile().params
    assert compiled_params["request_id"] == "test-req-001"
    assert compiled_params["attack_type"] == "sqli"
    assert compiled_params["action_taken"] == "block"
    assert compiled_params["is_attack"] is True


# ── Test 3: get_incidents returns mapped rows ─────────────────────────────────

@pytest.mark.asyncio
async def test_get_incidents_returns_rows():
    """
    Given: the DB has two incident rows
    When:  get_incidents() is called
    Then:  both rows are returned in the correct shape

    We simulate the .mappings().all() result that asyncpg/SQLAlchemy returns.
    """
    from shared.db.crud import get_incidents

    fake_rows = [
        {"id": 1, "request_id": "r1", "attack_type": "sqli", "action_taken": "block"},
        {"id": 2, "request_id": "r2", "attack_type": "xss", "action_taken": "block"},
    ]

    # Build a mock result that supports .mappings().all()
    mock_result = MagicMock()
    mock_result.mappings.return_value.all.return_value = fake_rows

    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=mock_result)

    with patch("shared.db.crud.get_conn", return_value=_make_conn_cm(conn)):
        rows = await get_incidents(limit=10, offset=0)

    assert len(rows) == 2
    assert rows[0]["attack_type"] == "sqli"
    assert rows[1]["attack_type"] == "xss"
    conn.execute.assert_called_once()


# ── Test 4: get_incidents filters by attack_type ──────────────────────────────

@pytest.mark.asyncio
async def test_get_incidents_filters_by_attack_type():
    """
    Given: a filter of attack_type="sqli"
    When:  get_incidents(attack_type="sqli") is called
    Then:  the SELECT is executed (with the WHERE clause applied by SQLAlchemy)

    We don't inspect the WHERE clause internals (SQLAlchemy's job), but we
    verify that execute() is called exactly once — the query ran.
    """
    from shared.db.crud import get_incidents

    mock_result = MagicMock()
    mock_result.mappings.return_value.all.return_value = []

    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=mock_result)

    with patch("shared.db.crud.get_conn", return_value=_make_conn_cm(conn)):
        await get_incidents(attack_type="sqli")

    conn.execute.assert_called_once()


# ── Test 5: get_setting returns value when key exists ────────────────────────

@pytest.mark.asyncio
async def test_get_setting_returns_value():
    """
    Given: the settings table has key="sensitivity_threshold" → value="0.7"
    When:  get_setting("sensitivity_threshold") is called
    Then:  "0.7" is returned
    """
    from shared.db.crud import get_setting

    mock_result = MagicMock()
    mock_result.first.return_value = ("0.7",)  # SQLAlchemy returns a row tuple

    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=mock_result)

    with patch("shared.db.crud.get_conn", return_value=_make_conn_cm(conn)):
        value = await get_setting("sensitivity_threshold")

    assert value == "0.7"


# ── Test 6: get_setting returns None when key is missing ──────────────────────

@pytest.mark.asyncio
async def test_get_setting_returns_none_for_missing_key():
    """
    Given: the settings table does NOT have key="nonexistent"
    When:  get_setting("nonexistent") is called
    Then:  None is returned (not an exception — missing keys are normal)

    Why: the worker config_subscriber calls get_setting() at startup to seed
    its in-memory config. It must handle missing keys gracefully.
    """
    from shared.db.crud import get_setting

    mock_result = MagicMock()
    mock_result.first.return_value = None  # no row found

    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=mock_result)

    with patch("shared.db.crud.get_conn", return_value=_make_conn_cm(conn)):
        value = await get_setting("nonexistent")

    assert value is None


# ── Test 7: upsert_setting commits to DB ──────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_setting_commits():
    """
    Given: a new key-value pair for the settings table
    When:  upsert_setting("sensitivity_threshold", "0.5") is called
    Then:  conn.execute() and conn.commit() are both called

    upsert = INSERT ... ON CONFLICT DO UPDATE. This is how the dashboard
    changes settings without first checking if the key already exists.
    """
    from shared.db.crud import upsert_setting

    conn = AsyncMock()
    conn.execute = AsyncMock()
    conn.commit = AsyncMock()

    with patch("shared.db.crud.get_conn", return_value=_make_conn_cm(conn)):
        await upsert_setting("sensitivity_threshold", "0.5")

    conn.execute.assert_called_once()
    conn.commit.assert_called_once()
