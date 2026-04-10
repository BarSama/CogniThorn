"""Deep Path: Gemini 1.5 Flash analysis with Redis caching."""
import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field

import google.generativeai as genai

from shared.config.settings import settings
from shared.redis_client import get_redis
from shared.schemas import RequestContext, Verdict

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security analyst reviewing an HTTP request flagged as potentially malicious.
Analyze the request and respond ONLY with valid JSON matching this exact schema:
{
  "is_attack": <boolean>,
  "attack_type": "<sqli|xss|path_traversal|rce|none>",
  "confidence": <float 0.0-1.0>,
  "explanation": "<one clear sentence for a human operator>",
  "affected_parameter": "<parameter name or null>",
  "remediation_hint": "<brief fix suggestion or null>"
}
Do not include any text outside the JSON object."""


# ── Circuit Breaker ────────────────────────────────────────────────────────────
#
# What is a circuit breaker?
# Named after the electrical version: normally current flows freely (closed).
# When something goes wrong, the breaker trips (opens) and stops all current
# until the problem is fixed. In software:
#   CLOSED  → normal — Gemini calls go through
#   OPEN    → broken — Gemini calls are skipped; fail-open immediately
#   HALF-OPEN → trial — one request is allowed through to test if Gemini recovered
#
# Why 3 strikes and 60 seconds?
# 3 consecutive failures is enough signal that Gemini is having trouble (not just
# one flaky request). 60 seconds lets the API recover before we retry. These
# values are configurable; adjust based on your Gemini SLA and traffic patterns.
#
# Blind spot for learners: this circuit breaker is in-process (one per worker).
# If you have 5 WAF workers, each has its own counter. Worker 1 might open its
# circuit while Worker 2 is still hammering Gemini. A shared Redis-based circuit
# breaker (store failure count in Redis) would coordinate all workers. That's a
# Phase 5/6 improvement.

@dataclass
class _CircuitBreaker:
    failures: int = 0
    state: str = "closed"   # closed | open | half-open
    opened_at: float = 0.0
    THRESHOLD: int = 3
    RESET_TIMEOUT: float = 60.0

    def record_success(self) -> None:
        if self.state != "closed":
            logger.info("Gemini circuit breaker CLOSED — API recovered")
        self.failures = 0
        self.state = "closed"

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.THRESHOLD and self.state == "closed":
            self.state = "open"
            self.opened_at = time.monotonic()
            logger.critical(
                "Gemini circuit breaker OPENED after %d consecutive failures. "
                "All requests will fail-open for %ds.",
                self.failures, int(self.RESET_TIMEOUT),
            )

    def allow_request(self) -> bool:
        """Return True if a Gemini request should be allowed through."""
        if self.state == "closed":
            return True
        if self.state == "open":
            elapsed = time.monotonic() - self.opened_at
            if elapsed > self.RESET_TIMEOUT:
                self.state = "half-open"
                logger.warning("Gemini circuit breaker entering HALF-OPEN — testing one request")
                return True   # allow one trial request
            return False      # still open
        # half-open: allow through (trial request)
        return True


_breaker = _CircuitBreaker()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_payload_hash(ctx: RequestContext) -> str:
    """SHA-256 of the normalized suspicious content for Redis cache key."""
    content = f"{ctx.method}:{ctx.path}:{ctx.query_string}:{ctx.body[:512]}"
    return hashlib.sha256(content.encode()).hexdigest()


def _fail_open_verdict(reason: str) -> Verdict:
    return Verdict(
        is_attack=False,
        attack_type="none",
        confidence=0.0,
        explanation=reason,
    )


async def _increment_fail_open(redis) -> None:
    try:
        await redis.incr("cognithhorn:stats:fail_open_count")
        await redis.expire("cognithhorn:stats:fail_open_count", 600)
    except Exception:
        pass


# ── Main analysis function ────────────────────────────────────────────────────

async def analyze(ctx: RequestContext) -> Verdict:
    """
    Analyze a suspicious request using Gemini Flash.
    Checks Redis cache first. On Gemini timeout or error, fails open.
    Circuit breaker prevents hammering a degraded API.
    """
    cache_key = f"cognithhorn:analysis:{_make_payload_hash(ctx)}"
    redis = get_redis()

    # --- Cache check ---
    try:
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            logger.debug("Gemini cache hit for %s %s", ctx.method, ctx.path)
            return Verdict(**data, from_cache=True)
    except Exception as e:
        logger.warning("Redis cache read failed: %s", e)

    # --- Circuit breaker check ---
    if not _breaker.allow_request():
        logger.warning(
            "Gemini circuit breaker is OPEN — failing open for %s %s", ctx.method, ctx.path
        )
        await _increment_fail_open(redis)
        return _fail_open_verdict("Gemini circuit breaker open — request passed (fail-open policy)")

    # --- Gemini API call ---
    try:
        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=SYSTEM_PROMPT,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.0,
            ),
        )
        prompt = (
            f"METHOD: {ctx.method}\n"
            f"PATH: {ctx.path}\n"
            f"QUERY: {ctx.query_string}\n"
            f"USER-AGENT: {ctx.user_agent or 'unknown'}\n"
            f"BODY:\n{ctx.body[:2048]}"
        )
        # Retry with exponential backoff on 429 (rate limit)
        # 429 is NOT a circuit-breaker failure — it means Gemini is up but busy.
        for attempt in range(3):
            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(model.generate_content, prompt),
                    timeout=5.0,
                )
                break
            except asyncio.TimeoutError:
                raise
            except Exception as e:
                if "429" in str(e) and attempt < 2:
                    wait = 2 ** attempt
                    logger.warning("Gemini 429, retrying in %ds", wait)
                    await asyncio.sleep(wait)
                else:
                    raise

        data = json.loads(response.text)
        verdict = Verdict(**data)

        # Success — close circuit if it was half-open
        _breaker.record_success()

        # --- Cache the result ---
        try:
            ttl = int(await redis.get("cognithhorn:settings:analysis_cache_ttl") or 86400)
            await redis.set(cache_key, json.dumps(data), ex=ttl)
        except Exception as e:
            logger.warning("Redis cache write failed: %s", e)

        return verdict

    except asyncio.TimeoutError:
        logger.critical("Gemini timeout (>5s) — failing open for %s %s", ctx.method, ctx.path)
        _breaker.record_failure()
        await _increment_fail_open(redis)
        return _fail_open_verdict("AI analysis timed out — request passed (fail-open policy)")

    except Exception as exc:
        logger.critical("Gemini analysis failed — failing open: %s", exc, exc_info=True)
        # Only count as circuit-breaker failure if it looks like a 5xx server error
        err_str = str(exc)
        if any(code in err_str for code in ("500", "502", "503", "504")):
            _breaker.record_failure()
        await _increment_fail_open(redis)
        return _fail_open_verdict("AI analysis error — request passed (fail-open policy)")

