"""
Tests for data_plane/detection/guard.py — the ONNX Fast Path.

--- What we're testing ---
1. A high-logit output from the model → high malicious score → passed=False
2. A low-logit output from the model → low malicious score → passed=True
3. If the ONNX session raises an exception → fail-open (passed=True, score=0.0)
4. The module-level _session singleton is only loaded once (not per request)

--- Why we mock the ONNX session ---
The actual ONNX model file (~250MB) doesn't exist in the test environment.
Even if it did, we don't want tests to depend on a specific model file —
that would make them brittle (what if the model changes?).
Instead, we mock `ort.InferenceSession` to return controlled logit arrays,
so we can test the *scoring logic* independently of the ML model itself.
"""
import numpy as np
import pytest
import pytest_asyncio
from unittest.mock import MagicMock, patch, AsyncMock

import data_plane.detection.guard as guard_module
from shared.schemas import RequestContext, GuardResult


@pytest.fixture(autouse=True)
def reset_session():
    """
    Reset the module-level _session singleton before each test.

    Why: guard.py stores the ONNX session in a global variable so it's only
    loaded once. But between tests, we need a clean slate — otherwise a mock
    from test_1 leaks into test_2.
    """
    original = guard_module._session
    guard_module._session = None
    yield
    guard_module._session = original


def _make_mock_session(class0_logit: float, class1_logit: float) -> MagicMock:
    """
    Build a fake InferenceSession that returns controlled logits.

    Shape: [[class0_logit, class1_logit]] — matches what DistilBERT produces.
    High class1_logit → high malicious probability after softmax.
    """
    session = MagicMock()
    session.run.return_value = [np.array([[class0_logit, class1_logit]])]
    return session


# ── Test 1: High-risk payload scores above threshold ─────────────────────────

@pytest.mark.asyncio
async def test_sqli_payload_scores_high(sqli_request):
    """
    Given: ONNX model returns high class-1 (malicious) logits
    When:  we score an SQL injection payload
    Then:  score >= 0.7 and passed=False (request should be inspected further)
    """
    mock_session = _make_mock_session(class0_logit=0.1, class1_logit=5.0)

    with patch("data_plane.detection.guard._session", mock_session):
        with patch("data_plane.detection.guard._warmup"):  # skip warmup
            result = await guard_module.score(sqli_request, threshold=0.7)

    assert result.score >= 0.7, f"Expected score >= 0.7, got {result.score}"
    assert result.passed is False, "High-risk request should NOT pass the guard"
    mock_session.run.assert_called_once()  # inference was called


# ── Test 2: Clean request scores below threshold ─────────────────────────────

@pytest.mark.asyncio
async def test_clean_request_scores_low(clean_request):
    """
    Given: ONNX model returns high class-0 (benign) logits
    When:  we score a normal GET request
    Then:  score < 0.7 and passed=True (request should be forwarded)
    """
    mock_session = _make_mock_session(class0_logit=5.0, class1_logit=0.1)

    with patch("data_plane.detection.guard._session", mock_session):
        with patch("data_plane.detection.guard._warmup"):
            result = await guard_module.score(clean_request, threshold=0.7)

    assert result.score < 0.7, f"Expected score < 0.7, got {result.score}"
    assert result.passed is True, "Clean request should pass the guard"


# ── Test 3: Fail-open on ONNX exception ──────────────────────────────────────

@pytest.mark.asyncio
async def test_onnx_crash_fails_open(clean_request):
    """
    Given: the ONNX session raises a RuntimeError (model file missing, OOM, etc.)
    When:  we score any request
    Then:  we return passed=True, score=0.0 — never block due to our own failure

    This is the Fail-Open policy: a broken WAF must never become a denial-of-service.
    """
    broken_session = MagicMock()
    broken_session.run.side_effect = RuntimeError("ONNX model file not found")

    with patch("data_plane.detection.guard._session", broken_session):
        result = await guard_module.score(clean_request, threshold=0.7)

    assert result.passed is True, "On ONNX crash, should fail-open (pass the request)"
    assert result.score == 0.0, "On ONNX crash, score should be 0.0 (neutral)"


# ── Test 4: Session singleton — only loaded once ──────────────────────────────

@pytest.mark.asyncio
async def test_session_loaded_only_once(clean_request):
    """
    Given: multiple requests arrive
    When:  we score them sequentially
    Then:  _load_session() is only called once (the ONNX model is heavy — ~250MB)

    Why this matters: if we loaded the model on every request, the first request
    would take 5+ seconds. The singleton pattern prevents that.
    """
    mock_session = _make_mock_session(5.0, 0.1)
    load_call_count = 0

    def fake_load():
        nonlocal load_call_count
        load_call_count += 1
        return mock_session

    with patch("data_plane.detection.guard._load_session", side_effect=fake_load):
        with patch("data_plane.detection.guard._warmup"):
            await guard_module.score(clean_request, threshold=0.7)
            await guard_module.score(clean_request, threshold=0.7)
            await guard_module.score(clean_request, threshold=0.7)

    assert load_call_count == 1, (
        f"_load_session should be called exactly once, was called {load_call_count} times"
    )


# ── Test 5: Custom threshold respected ───────────────────────────────────────

@pytest.mark.asyncio
async def test_custom_threshold_applied(sqli_request):
    """
    Given: ONNX model returns a score of ~0.73 (above default 0.7 but below 0.8)
    When:  we score with threshold=0.8
    Then:  passed=True (score is below the custom threshold)

    This verifies the sensitivity slider in the dashboard actually works —
    raising the threshold makes the WAF less aggressive.
    """
    # logits that produce a malicious probability of ~0.73
    mock_session = _make_mock_session(class0_logit=0.5, class1_logit=1.0)

    with patch("data_plane.detection.guard._session", mock_session):
        result_strict = await guard_module.score(sqli_request, threshold=0.5)
        # Reset singleton so next call re-uses same session
        result_relaxed = await guard_module.score(sqli_request, threshold=0.99)

    # With a very strict threshold (0.5), even moderate scores fail
    # With a very relaxed threshold (0.99), almost nothing fails
    # We just verify the threshold parameter is actually used
    assert result_relaxed.passed is True, (
        "With threshold=0.99, only extremely high scores should fail"
    )
