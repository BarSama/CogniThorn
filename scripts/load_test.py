"""
CogniThorn WAF Load Test — using Locust.

--- What this tests ---
Simulates a realistic traffic mix against the SSL Gateway (port 80):
  80% clean requests — GET and POST requests that should pass through
  15% attack requests — SQLi and XSS payloads that should be blocked
   5% edge cases — large bodies, unusual methods, Unicode

All requests include a Host header so the SSL Gateway can route them
to the correct upstream.

--- What to measure ---
After running, look for:
  - Median (P50) response time < 20ms for clean requests (Fast Path only)
  - P99 response time < 100ms (includes some Deep Path requests)
  - 403 response rate ≈ attack % (15% of requests)
  - Zero 5xx errors (5xx = WAF or upstream error, not attack block)
  - Fail-open count in Redis stays at 0 during normal load

--- How to run ---
  # Install locust (dev only — not in production containers):
  pip install locust

  # Start the full stack first:
  docker compose up -d

  # Run load test (open browser at http://localhost:8089 to control it):
  locust -f scripts/load_test.py --host http://localhost

  # Run headless (no browser) for 60s at 100 concurrent users:
  locust -f scripts/load_test.py --host http://localhost \\
    --headless --users 100 --spawn-rate 10 --run-time 60s

--- Reading the results ---
  Locust reports:
    RPS  = requests per second (throughput)
    50%  = median latency (half of requests faster than this)
    95%  = 95th percentile (only 5% of requests slower than this)
    99%  = 99th percentile (the "worst case" you see in practice)
    Fail = non-2xx/3xx/403 responses (403 is expected for attacks, not a failure)

  Target for WAF Fast Path:
    P50 < 20ms, P95 < 50ms, P99 < 100ms

  If P99 is high, it's usually one of:
    1. Gemini Deep Path being called (expected: ~10-15% of requests)
    2. Redis Sentinel failover happening (add more replicas)
    3. ONNX model not warmed up yet (wait 10s after startup)
"""
import random
from locust import HttpUser, task, between, events

# The Host header tells the SSL Gateway which upstream to route to.
# This must match a domain you've configured via POST /api/domains.
_HOST_HEADER = "app.example.com"

_CLEAN_PATHS = [
    ("/api/users", "GET", None),
    ("/api/products?category=electronics&page=1", "GET", None),
    ("/dashboard", "GET", None),
    ("/health", "GET", None),
    ("/api/search?q=best+laptop+2024", "GET", None),
    ("/api/articles/getting-started", "GET", None),
]

_CLEAN_POSTS = [
    ("/api/login",    {"email": "alice@example.com", "password": "SecurePass123"}),
    ("/api/register", {"username": "bob", "email": "bob@example.com"}),
    ("/api/feedback", {"rating": "5", "comment": "Great product!"}),
    ("/api/orders",   {"item_id": "42", "qty": "2"}),
]

_SQLI_PAYLOADS = [
    "admin' OR '1'='1' --",
    "1 UNION SELECT NULL,username,password FROM users--",
    "1' AND SLEEP(3)--",
    "admin'/**/OR/**/1=1--",
]

_XSS_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]


class WAFUser(HttpUser):
    """
    Simulates a user browsing an app protected by CogniThorn.
    wait_time = 0.05–0.5s between requests → realistic think time.
    """
    wait_time = between(0.05, 0.5)

    def _headers(self):
        return {"Host": _HOST_HEADER}

    # ── Clean traffic (80%) ───────────────────────────────────────────────────

    @task(5)
    def clean_get(self):
        """Normal GET request — should be fast (ONNX only, no Gemini)."""
        path, method, _ = random.choice(_CLEAN_PATHS)
        self.client.get(path, headers=self._headers(), name="clean_GET")

    @task(3)
    def clean_post(self):
        """Normal POST request — should be fast."""
        path, data = random.choice(_CLEAN_POSTS)
        self.client.post(path, data=data, headers=self._headers(), name="clean_POST")

    # ── Attack traffic (15%) ──────────────────────────────────────────────────
    # We expect 403 responses here. Locust counts non-2xx as failures by default;
    # we catch the response to mark 403 as expected (not a failure).

    @task(1)
    def sqli_attack(self):
        """SQL injection in login body — should be blocked (403)."""
        payload = random.choice(_SQLI_PAYLOADS)
        with self.client.post(
            "/api/login",
            data={"username": payload, "password": "x"},
            headers=self._headers(),
            name="attack_SQLi",
            catch_response=True,
        ) as resp:
            if resp.status_code == 403:
                resp.success()  # 403 is the expected WAF response
            elif resp.status_code == 200:
                resp.failure("SQLi was NOT blocked — potential WAF miss")

    @task(1)
    def xss_attack(self):
        """XSS payload in search query — should be blocked (403)."""
        payload = random.choice(_XSS_PAYLOADS)
        with self.client.get(
            f"/api/search?q={payload}",
            headers=self._headers(),
            name="attack_XSS",
            catch_response=True,
        ) as resp:
            if resp.status_code == 403:
                resp.success()
            elif resp.status_code == 200:
                resp.failure("XSS was NOT blocked — potential WAF miss")

    # ── Edge cases (5%) ───────────────────────────────────────────────────────

    @task(1)
    def large_body(self):
        """POST with a large body — tests body size limiting."""
        body = "A" * (60 * 1024)  # 60KB (just under default 64KB limit)
        self.client.post(
            "/api/upload",
            data=body,
            headers={**self._headers(), "Content-Type": "text/plain"},
            name="edge_large_body",
        )

    @task(1)
    def unicode_content(self):
        """Request with non-ASCII content — tests Unicode safety."""
        self.client.post(
            "/api/translate",
            data={"text": "データベースの使い方について質問があります"},
            headers=self._headers(),
            name="edge_unicode",
        )


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("\n" + "─" * 60)
    print("CogniThorn WAF Load Test Starting")
    print("Target: http://localhost (SSL Gateway)")
    print("Mix: 80% clean | 15% attacks | 5% edge cases")
    print("Expected: attacks return 403 (counted as success)")
    print("─" * 60 + "\n")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    stats = environment.stats.total
    print("\n" + "─" * 60)
    print("Load Test Complete")
    print(f"  Total requests : {stats.num_requests}")
    print(f"  Failures       : {stats.num_failures}  (should be 0 — 403 is not a failure)")
    print(f"  RPS            : {stats.current_rps:.1f}")
    print(f"  P50 latency    : {stats.get_response_time_percentile(0.50):.0f}ms  (target <20ms)")
    print(f"  P95 latency    : {stats.get_response_time_percentile(0.95):.0f}ms  (target <50ms)")
    print(f"  P99 latency    : {stats.get_response_time_percentile(0.99):.0f}ms  (target <100ms)")
    print()
    print("Check fail-open count (should be 0):")
    print("  redis-cli -h localhost hget cognithhorn:stats fail_open_count")
    print("─" * 60 + "\n")
