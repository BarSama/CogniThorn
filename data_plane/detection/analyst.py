"""Deep Path: Gemini 1.5 Flash analysis with Redis caching."""
import asyncio
import hashlib
import json
import logging

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


def _make_payload_hash(ctx: RequestContext) -> str:
    """SHA-256 of the normalized suspicious content for Redis cache key."""
    content = f"{ctx.method}:{ctx.path}:{ctx.query_string}:{ctx.body[:512]}"
    return hashlib.sha256(content.encode()).hexdigest()


async def analyze(ctx: RequestContext) -> Verdict:
    """
    Analyze a suspicious request using Gemini Flash.
    Checks Redis cache first. On Gemini timeout or error, fails open.
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
        # Retry with exponential backoff on 429
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

        # --- Cache the result ---
        try:
            ttl = int(await redis.get("cognithhorn:settings:analysis_cache_ttl") or 86400)
            await redis.set(cache_key, json.dumps(data), ex=ttl)
        except Exception as e:
            logger.warning("Redis cache write failed: %s", e)

        return verdict

    except asyncio.TimeoutError:
        logger.critical("Gemini timeout (>5s) — failing open for %s %s", ctx.method, ctx.path)
        await _increment_fail_open(redis)
        return Verdict(
            is_attack=False,
            attack_type="none",
            confidence=0.0,
            explanation="AI analysis timed out — request passed (fail-open policy)",
        )
    except Exception as exc:
        logger.critical("Gemini analysis failed — failing open: %s", exc, exc_info=True)
        await _increment_fail_open(redis)
        return Verdict(
            is_attack=False,
            attack_type="none",
            confidence=0.0,
            explanation=f"AI analysis error — request passed (fail-open policy)",
        )


async def _increment_fail_open(redis) -> None:
    try:
        await redis.incr("cognithhorn:stats:fail_open_count")
        # expire after 10 minutes so the alert auto-clears
        await redis.expire("cognithhorn:stats:fail_open_count", 600)
    except Exception:
        pass
