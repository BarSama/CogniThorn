"""
Tests for data_plane/detection/analyst.py — the Gemini Deep Path.

--- What we're testing ---
1. Redis cache HIT: pre-populate cache → Gemini API is never called
2. Redis cache MISS: Redis returns nothing → Gemini IS called → result stored in cache
3. Gemini confirms an attack → Verdict(is_attack=True)
4. Gemini says false positive → Verdict(is_attack=False)
5. Gemini times out → fail-open (is_attack=False, logs CRITICAL)
6. Gemini returns HTTP 429 → retries with backoff → eventually succeeds

--- Why the Redis cache matters for the free Gemini tier ---
Gemini Flash's free tier allows 15 requests per minute. A busy app could
easily get 100 identical SQLi attempts per minute (automated scanner).
Without the cache, we'd burn all 15 RPM on the same payload and then
fail-open for the remaining 85 requests. The SHA-256 cache means we only
call Gemini ONCE per unique payload pattern, regardless of how many times
it's seen.
"""
import asyncio
import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import data_plane.detection.analyst as analyst_module


# ── Helper: build a fake Gemini response ─────────────────────────────────────

def _gemini_response(is_attack: bool, attack_type: str = "sqli",
                     confidence: float = 0.95) -> MagicMock:
    """Return a mock object that looks like a Gemini API response."""
    resp = MagicMock()
    resp.text = json.dumps({
        "is_attack": is_attack,
        "attack_type": attack_type,
        "confidence": confidence,
        "explanation": "Test explanation from mock Gemini.",
        "affected_parameter": "username" if is_attack else None,
        "remediation_hint": "Use parameterized queries." if is_attack else None,
    })
    return resp


# ── Test 1: Cache hit — Gemini NOT called ────────────────────────────────────

@pytest.mark.asyncio
async def test_cache_hit_skips_gemini(sqli_request, mock_redis):
    """
    Given: Redis already has a cached verdict for this payload hash
    When:  we analyze the request
    Then:  Gemini API is never called (saves quota, instant response)
    """
    cached_verdict = {
        "is_attack": True,
        "attack_type": "sqli",
        "confidence": 0.97,
        "explanation": "Cached: SQL injection detected.",
        "affected_parameter": "username",
        "remediation_hint": None,
        "from_cache": False,
    }
    # Pre-populate the cache so Redis.get() returns the cached JSON
    mock_redis.get.return_value = json.dumps(cached_verdict)

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("google.generativeai.GenerativeModel") as mock_gemini:
            result = await analyst_module.analyze(sqli_request)

    mock_gemini.assert_not_called()  # Gemini was never instantiated
    assert result.is_attack is True
    assert result.from_cache is True
    assert result.attack_type == "sqli"


# ── Test 2: Cache miss — Gemini IS called and result is cached ───────────────

@pytest.mark.asyncio
async def test_cache_miss_calls_gemini_and_caches(sqli_request, mock_redis):
    """
    Given: Redis has no cached verdict (get returns None)
    When:  we analyze the request
    Then:  Gemini is called once, result is stored in Redis for future requests
    """
    mock_redis.get.return_value = None  # cache miss

    mock_model = MagicMock()
    mock_model.generate_content.return_value = _gemini_response(is_attack=True)

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("google.generativeai.configure"):
            with patch("google.generativeai.GenerativeModel", return_value=mock_model):
                with patch("google.generativeai.GenerationConfig"):
                    result = await analyst_module.analyze(sqli_request)

    # Gemini was called exactly once
    mock_model.generate_content.assert_called_once()
    # Result was stored in Redis
    mock_redis.set.assert_called_once()
    cache_key_arg = mock_redis.set.call_args[0][0]
    assert cache_key_arg.startswith("cognithhorn:analysis:"), (
        f"Cache key should start with 'cognithhorn:analysis:', got: {cache_key_arg}"
    )
    assert result.is_attack is True
    assert result.from_cache is False


# ── Test 3: Gemini identifies a false positive ───────────────────────────────

@pytest.mark.asyncio
async def test_gemini_returns_false_positive(sqli_request, mock_redis):
    """
    Given: ONNX scored this request as suspicious (score >= 0.7)
    But:   Gemini determines it's actually a legitimate request
    Then:  Verdict.is_attack=False — the request should be forwarded, not blocked

    Example: a developer testing their own /login page with the string
    "OR '1'='1'" in their test data could trigger the ONNX model.
    Gemini has more context and can recognise the full HTTP context is benign.
    """
    mock_redis.get.return_value = None

    mock_model = MagicMock()
    mock_model.generate_content.return_value = _gemini_response(
        is_attack=False, attack_type="none", confidence=0.89
    )

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("google.generativeai.configure"):
            with patch("google.generativeai.GenerativeModel", return_value=mock_model):
                with patch("google.generativeai.GenerationConfig"):
                    result = await analyst_module.analyze(sqli_request)

    assert result.is_attack is False
    assert result.attack_type == "none"


# ── Test 4: Gemini timeout → fail-open ───────────────────────────────────────

@pytest.mark.asyncio
async def test_gemini_timeout_fails_open(sqli_request, mock_redis):
    """
    Given: Gemini API takes longer than 5 seconds (network issue, rate limit)
    When:  asyncio.wait_for times out
    Then:  request is PASSED (fail-open) — never block due to our own timeout

    Why 5 seconds? The WAF adds latency to every request. A user waiting
    >5s for a page load due to Gemini is a worse experience than a false
    negative. We choose availability over perfect accuracy on timeouts.
    """
    mock_redis.get.return_value = None

    async def slow_gemini(*args, **kwargs):
        await asyncio.sleep(10)  # simulate timeout
        return _gemini_response(is_attack=True)

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("google.generativeai.configure"):
            with patch("asyncio.to_thread", side_effect=asyncio.TimeoutError()):
                result = await analyst_module.analyze(sqli_request)

    assert result.is_attack is False, (
        "On Gemini timeout, must fail-open (is_attack=False)"
    )
    assert result.confidence == 0.0


# ── Test 5: Gemini 429 → retry with backoff ──────────────────────────────────

@pytest.mark.asyncio
async def test_gemini_429_retries(sqli_request, mock_redis):
    """
    Given: Gemini returns HTTP 429 (rate limited) on the first attempt
    When:  the retry logic kicks in
    Then:  second attempt succeeds and returns a valid verdict

    The free tier is 15 RPM. Under attack traffic, this limit can be hit.
    The retry with exponential backoff means a brief pause before trying again.
    """
    mock_redis.get.return_value = None

    call_count = 0
    success_response = _gemini_response(is_attack=True)

    def gemini_429_then_success(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("429 Too Many Requests")
        return success_response

    mock_model = MagicMock()
    mock_model.generate_content.side_effect = gemini_429_then_success

    with patch("shared.redis_client.get_redis", return_value=mock_redis):
        with patch("google.generativeai.configure"):
            with patch("google.generativeai.GenerativeModel", return_value=mock_model):
                with patch("google.generativeai.GenerationConfig"):
                    with patch("asyncio.sleep", new_callable=AsyncMock):  # skip real sleep
                        result = await analyst_module.analyze(sqli_request)

    assert call_count == 2, f"Expected 2 Gemini calls (1 fail + 1 retry), got {call_count}"
    assert result.is_attack is True


# ── Test 6: Same payload hash → same cache key ───────────────────────────────

def test_same_payload_produces_same_hash(sqli_request):
    """
    Given: two RequestContext objects with identical method/path/query/body
    When:  we compute the payload hash
    Then:  both produce the same SHA-256 hash

    This is critical: if the hash were non-deterministic (e.g. using id() or
    timestamps), we'd get cache misses every time and the 15 RPM limit would
    be exhausted instantly.
    """
    from data_plane.detection.analyst import _make_payload_hash
    from shared.schemas import RequestContext

    ctx1 = RequestContext(
        request_id="id-1",  # different request_id
        method="POST",
        path="/login",
        query_string="",
        body="username=admin' OR '1'='1'",
    )
    ctx2 = RequestContext(
        request_id="id-2",  # different request_id — should NOT affect hash
        method="POST",
        path="/login",
        query_string="",
        body="username=admin' OR '1'='1'",
    )

    assert _make_payload_hash(ctx1) == _make_payload_hash(ctx2), (
        "Same payload must produce the same cache key regardless of request_id"
    )
