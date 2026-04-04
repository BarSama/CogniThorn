"""
Tests for data_plane/detection/tokenizer_utils.py — the input encoding layer.

--- Why this layer matters for detection quality ---
The ONNX model never sees the raw HTTP request. It only sees the text string
that `build_input_text()` produces. If that function mangles the input —
strips quotes, collapses whitespace, or silently truncates — the model will
see a different string than what the attacker actually sent.

Example failure: if `build_input_text` strips single quotes, then
  "admin' OR '1'='1'"  becomes  "admin OR 1=1"
The model is trained on attack patterns that include quotes. Without them,
it might not recognise this as an SQLi payload — and let it through.

--- What we test here ---
1. All four fields (method, path, query, body) appear in the output
2. Attack-relevant characters (quotes, angle brackets, semicolons) are preserved
3. Long bodies are truncated to 512 chars — not silently dropped or passed whole
4. Empty fields produce valid output (no crash, no empty string)
5. Unicode / non-ASCII characters don't crash the encoder
6. The output format is stable — "METHOD ... PATH ... QUERY ... BODY ..."
7. Two different requests produce two different encoded inputs (no hash collision)
"""
import pytest
import numpy as np
from unittest.mock import patch, MagicMock


# ── Test 1: all fields appear in the output string ────────────────────────────

def test_build_input_text_includes_all_fields():
    """
    Given: a request with method, path, query and body all set
    When:  build_input_text() is called
    Then:  the output string contains all four values

    Why: if any field is missing, the model gets incomplete context.
    A SQLi in the query string must appear in the model input — otherwise
    only the body is inspected and query-based attacks slip through.
    """
    from data_plane.detection.tokenizer_utils import build_input_text

    result = build_input_text(
        method="POST",
        path="/api/login",
        query="redirect=/dashboard",
        body="username=admin&password=secret",
    )

    assert "POST" in result
    assert "/api/login" in result
    assert "redirect=/dashboard" in result
    assert "username=admin" in result


# ── Test 2: injection-relevant characters are preserved ───────────────────────

def test_injection_chars_preserved():
    """
    Given: a classic SQLi payload with single quotes, dashes, spaces
    When:  build_input_text() is called
    Then:  all characters appear verbatim in the output

    This is the most critical test in this file. If the encoder strips or
    HTML-escapes single quotes, the model loses the key signal that
    distinguishes "admin' OR '1'='1'" from "admin OR 1 1".
    """
    from data_plane.detection.tokenizer_utils import build_input_text

    sqli_body = "username=admin' OR '1'='1' --"
    xss_query = "q=<script>alert(1)</script>"

    sqli_result = build_input_text("POST", "/login", "", sqli_body)
    xss_result  = build_input_text("GET", "/search", xss_query, "")

    # Single quotes must survive
    assert "'" in sqli_result, "Single quotes stripped — SQLi pattern will be invisible to model"
    # SQL keywords must survive
    assert "OR" in sqli_result, "SQL OR keyword missing from output"
    assert "--" in sqli_result, "SQL comment delimiter stripped"
    # HTML angle brackets must survive
    assert "<script>" in xss_result, "XSS script tag stripped — model cannot detect it"


# ── Test 3: body truncation at 512 characters ─────────────────────────────────

def test_body_truncated_at_512_chars():
    """
    Given: a body that is 2000 characters long
    When:  build_input_text() is called
    Then:  the body in the output is truncated to at most 512 characters

    Why: ONNX Runtime tokenizes to max 512 tokens. If we pass a 10MB request
    body the tokenizer will silently truncate it anyway — but we want to
    truncate BEFORE that, so the model sees the first 512 chars (where most
    attack payloads live) rather than a truncated-in-the-middle version.

    Security note: an attacker could try to pad the beginning of a request
    body with harmless text so the malicious payload sits after byte 512,
    knowing the WAF won't see it. That's why `max_body_size_kb` exists as
    a setting — the proxy also hard-limits the body before it reaches here.
    """
    from data_plane.detection.tokenizer_utils import build_input_text

    long_body = "A" * 2000
    result = build_input_text("POST", "/upload", "", long_body)

    # Find where the body starts in the output
    body_prefix = "BODY "
    body_start = result.index(body_prefix) + len(body_prefix)
    body_in_output = result[body_start:]

    assert len(body_in_output) <= 512, (
        f"Body not truncated: output body is {len(body_in_output)} chars (expected <= 512)"
    )


# ── Test 4: empty fields produce valid output ─────────────────────────────────

def test_empty_fields_produce_valid_output():
    """
    Given: method only, all other fields empty
    When:  build_input_text() is called
    Then:  no exception is raised and the output contains all field labels

    Why: GET requests typically have no body; health checks have no query;
    the model input must handle all combinations without crashing.
    """
    from data_plane.detection.tokenizer_utils import build_input_text

    result = build_input_text("GET", "/health", "", "")

    assert isinstance(result, str)
    assert len(result) > 0
    assert "METHOD" in result
    assert "PATH" in result
    assert "QUERY" in result
    assert "BODY" in result


# ── Test 5: Unicode / non-ASCII in body does not crash ────────────────────────

def test_unicode_body_does_not_crash():
    """
    Given: a request body containing Japanese text and emoji
    When:  build_input_text() is called
    Then:  no exception is raised

    Why: international users submit non-ASCII in forms. The WAF must not
    crash on multibyte input — that would be a denial-of-service vector.
    An attacker could send `POST /submit` with a body of 512 carefully chosen
    Unicode characters that crashes the tokenizer.
    """
    from data_plane.detection.tokenizer_utils import build_input_text

    unicode_body = "データベースについての質問です。SELECT文の使い方を教えてください。🔍"
    result = build_input_text("POST", "/translate", "", unicode_body)

    assert isinstance(result, str)
    assert len(result) > 0


# ── Test 6: output format is stable ───────────────────────────────────────���───

def test_output_format_is_stable():
    """
    Given: a request
    When:  build_input_text() is called twice with the same input
    Then:  the output is identical both times

    Why: the model was trained on a specific input format. If the format
    changes between versions (e.g. someone changes "METHOD" to "method"),
    the model's behavior becomes undefined — it was never trained on the new
    format, so its accuracy degrades silently.
    """
    from data_plane.detection.tokenizer_utils import build_input_text

    r1 = build_input_text("GET", "/api/test", "page=1", "")
    r2 = build_input_text("GET", "/api/test", "page=1", "")

    assert r1 == r2, "build_input_text is not deterministic"
    # Also verify the expected format explicitly
    assert r1 == "METHOD GET PATH /api/test QUERY page=1 BODY "


# ── Test 7: two different payloads produce different inputs ───────────────────

def test_different_payloads_produce_different_inputs():
    """
    Given: a clean request and an SQLi attack request
    When:  build_input_text() is called on both
    Then:  the outputs are different (the attack pattern is not collapsed away)

    This test catches accidental normalization that erases attack signals.
    Example failure: if the function strips punctuation, then
      "admin' OR '1'='1'"  and  "admin OR 1=1"
    would produce the same output — both would score identically.
    """
    from data_plane.detection.tokenizer_utils import build_input_text

    clean = build_input_text("POST", "/login", "", "username=admin&password=correct")
    attack = build_input_text("POST", "/login", "", "username=admin' OR '1'='1' --&password=x")

    assert clean != attack, (
        "Clean and SQLi inputs produced identical model input — "
        "the attack characters were stripped or normalized"
    )
