# CogniThorn — Development Roadmap

> **Reading this as a learner:** Each phase below explains not just *what* to build,
> but *why* it comes in this order and what could go wrong if you skip it.
> Phases build on each other — don't add features on an untested security foundation.

---

## Current State (Completed)

The full codebase skeleton is written and pushed:
- `ssl_gateway/` — custom TLS termination + ACME + L7 routing
- `data_plane/` — ONNX fast path + Gemini deep path + Redis cache
- `control_plane/` — management API + Streamlit dashboard + self-healing
- `shared/` — shared DB models, settings, schemas
- `docker-compose.yml` — full HA stack (PostgreSQL + Redis Sentinel + PgBouncer)

**Known open issues before Phase 1:**
- [x] SSL Gateway HTTPS SNI wiring needs verification against uvicorn's SSL API
- [x] No tests exist yet — detection behaviour is unverified
- [ ] Control plane API has no authentication (any caller can change settings)
- [ ] `download_model.py` downloads a generic DistilBERT, not a WAF-specific model

---

## Phase 1 — Verification & Smoke Tests
> *"Does it actually run?"*
>
> **Why first:** You cannot trust any other phase until you can reliably start the stack,
> send a request, and confirm it was inspected. Everything else is built on this.

- [x] Fix SSL Gateway HTTPS server SNI context wiring
- [x] Write `tests/` suite:
  - [x] `test_guard.py` — ONNX scores SQLi/XSS payloads above threshold, clean requests below
  - [x] `test_analyst.py` — Gemini integration with mocked API responses
  - [x] `test_proxy.py` — full middleware flow: block path and pass-through path
  - [x] `test_db.py` — `log_incident_blocked` writes to DB; `increment_clean_counters` does not
  - [x] `test_worker_router.py` — round-robin selection, worker failover on 502
- [x] Add `pytest` + `pytest-asyncio` + `respx` (httpx mocker) to dev requirements (`requirements-dev.txt`)
- [ ] End-to-end smoke test: `docker compose up` → send SQLi → verify 403 → check dashboard
- [ ] Confirm `docker compose up --scale waf-worker=3` registers 3 workers at `/api/workers`
- [ ] CI: add GitHub Actions workflow that runs tests on every push

**Investigation tools for this phase:**
```bash
docker compose logs -f waf-worker          # watch inference logs
docker compose logs -f ssl-gateway         # watch TLS + routing logs
curl http://localhost:8090/api/workers     # confirm worker registry
redis-cli -h localhost hgetall cognithhorn:workers  # raw Redis state
```

---

## Phase 2 — Security Hardening
> *"Is the WAF itself secure?"*
>
> **Why second:** A WAF that is itself exploitable is worse than no WAF. Common attack
> surface: the management API, the dashboard, and the Redis/PostgreSQL connections.

- [ ] **API Authentication:** Add API key or JWT to the control plane API
  - Without this, anyone on the network can call `PUT /api/settings` and set threshold to `1.0` (disabling detection)
- [ ] **Rate-limit the management API:** Prevent brute-force or flood attacks on `/api/*`
- [ ] **Secrets management:** Move API keys out of the DB (plaintext) into env vars or a vault
- [ ] **Input validation on domains:** Prevent SSRF via malicious `upstream_url` values
  - *What is SSRF?* Server-Side Request Forgery — an attacker adds `upstream_url=http://169.254.169.254` to reach cloud metadata endpoints
- [ ] **TLS for internal services:** Currently workers talk to PostgreSQL and Redis over plain TCP inside Docker. Fine for single-host; add TLS for multi-host deployments.
- [ ] **`key_pem` encryption at rest:** Private keys are stored as plaintext in PostgreSQL. Encrypt them with a key derived from `POSTGRES_PASSWORD` before storing.
- [ ] **Audit log:** Every settings change should write who changed what and when

**Blind spot to flag:** The Redis `cognithhorn:workers` hash is writable by any container
on the Docker network. A compromised upstream app could register a fake worker and
intercept traffic. Phase 2 should add a shared secret for worker registration.

---

## Phase 3 — Detection Quality
> *"Does it actually catch attacks without crying wolf?"*
>
> **Why third:** The current ONNX model is a generic DistilBERT, not trained on WAF
> attack datasets. Until we validate detection quality, we don't know the false-positive
> rate. A WAF with 20% false positives is unusable in production.

- [ ] **Benchmark the default model:** Run standard attack datasets (OWASP CRS test suite,
  SQLMap payloads, XSS polyglots) and measure:
  - True positive rate (attacks correctly blocked)
  - False positive rate (legitimate requests incorrectly blocked)
- [ ] **Fine-tune or replace the model:** Identify a publicly available model trained on
  WAF/injection datasets (e.g. from HuggingFace security-focused repos)
- [ ] **Threshold calibration:** The default `0.7` is a guess. Plot a precision/recall curve
  to find the real optimal threshold for your traffic
- [ ] **Adversarial testing:** Try payload obfuscation (URL encoding, case variation,
  comment injection in SQL) to find evasion paths
- [ ] **False positive baseline:** Run the WAF against a real app's normal traffic and count
  how many legitimate requests get flagged

**Key concept — Why ML models need calibration:**
> A model trained on one dataset may have learned shortcuts (like "anything with the word
> SELECT is SQLi") that don't hold in the real world. Calibration means testing it against
> your *actual* traffic, not just the training data.

---

## Phase 4 — Performance & Reliability
> *"Can it handle real traffic without becoming a bottleneck?"*
>
> **Why fourth:** You need verified correctness (Phases 1–3) before performance matters.
> Optimising incorrect code is wasted effort.

- [ ] **Latency profiling:** Measure P50/P95/P99 of the full request path under load
  - Target: Fast Path < 20ms P99; total WAF overhead < 50ms P99
  - Tools: `wrk`, `k6`, or `locust` for load generation
- [ ] **ONNX model quantization:** INT8 quantization can reduce inference time by ~40%
  with minimal accuracy loss — reduces worker RAM from ~512MB to ~300MB
- [ ] **Connection pool tuning:** Benchmark PgBouncer pool size vs worker count
- [ ] **Redis pipeline:** Batch counter increments (`INCR`) into pipelines to reduce round-trips
- [ ] **Graceful shutdown:** Ensure workers drain in-flight requests before deregistering
  (prevents 502 errors during `docker compose up --scale`)
- [ ] **Circuit breaker for Gemini:** If Gemini returns 5xx 3 times in a row, stop sending
  requests for 60 seconds (fail-open) rather than hammering a degraded API

---

## Phase 5 — Observability
> *"Can you see what's happening inside the system in production?"*
>
> **Why this matters:** Without metrics and tracing, when something goes wrong in
> production you're flying blind. This is especially important for a security tool —
> you need to know *immediately* if detection degrades.

- [ ] **Prometheus metrics endpoint** on WAF workers:
  - `cognithhorn_requests_total` (counter, labels: action=pass/block/fp)
  - `cognithhorn_guard_latency_seconds` (histogram)
  - `cognithhorn_gemini_calls_total` (counter, labels: cached=true/false)
  - `cognithhorn_fail_open_total` (counter — alert on this)
- [ ] **Grafana dashboard:** Pre-built dashboard JSON for the above metrics
- [ ] **Structured logging:** Ensure all logs are JSON (machine-parseable by log aggregators)
- [ ] **Distributed tracing:** Add `request_id` propagation through SSL Gateway → Worker →
  upstream so you can trace a single request end-to-end
- [ ] **Alerting rules:** Alert if `fail_open_total` > 0 in 5 minutes, or if P99 latency
  exceeds 100ms

---

## Phase 6 — Multi-Tenancy & Advanced Routing
> *"Can multiple teams / apps use one CogniThorn deployment?"*

- [ ] **Per-domain sensitivity threshold:** Allow `app1.example.com` to use threshold `0.6`
  while `app2.example.com` uses `0.8`
- [ ] **Per-domain allow/block lists:** Static IP allowlists or path exclusions per domain
  (e.g. "never inspect `/api/webhook` for domain X")
- [ ] **Upstream health checks in SSL Gateway:** Currently workers detect upstream failures;
  the gateway should also health-check upstreams
- [ ] **Geo-blocking:** Optional rule to block traffic from specific countries (via IP geolocation)
- [ ] **Custom response pages:** Branded 403 page instead of raw JSON

---

## Phase 7 — Self-Healing Improvements
> *"Make the GitHub PR feature actually production-ready."*
>
> **Current state:** The self-healing PR generator works but sends patches to Gemini
> with limited context. It may produce incorrect patches.

- [ ] **PR review queue:** Instead of auto-opening PRs, add a "pending approval" queue in
  the dashboard — humans review before the PR is opened
- [ ] **Patch validation:** Run the patched code through a linter/SAST tool before opening PR
- [ ] **Language detection:** Auto-detect the file's language (Python/JS/PHP/etc.) and tailor
  the Gemini prompt accordingly
- [ ] **Duplicate PR prevention:** Check if a PR already exists for this file + attack type
  before opening another
- [ ] **Patch success tracking:** Did the developer merge the PR? Track merge status and
  show in dashboard

---

## Phase 8 — Community & Open Source Readiness

- [ ] **CONTRIBUTING.md:** How to set up local dev, run tests, submit PRs
- [ ] **Example apps:** A deliberately vulnerable Flask/Node app to demo CogniThorn against
- [ ] **Helm chart:** For users who want Kubernetes instead of Docker Compose
- [ ] **Plugin interface:** Allow custom detection modules (e.g. rate-limiting, bot detection)
  to plug in without modifying core code
- [ ] **Security policy (`SECURITY.md`):** How to report vulnerabilities in CogniThorn itself
- [ ] **Changelog + versioning:** Semantic versioning, changelog automation

---

## Priority Matrix

| Phase | Risk if skipped | Effort | Do first? |
|---|---|---|---|
| 1 — Verification | **Critical** — nothing works | Medium | ✅ Yes |
| 2 — Security Hardening | **Critical** — WAF is exploitable | Medium | ✅ Yes |
| 3 — Detection Quality | **High** — false positives kill adoption | High | ✅ Yes |
| 4 — Performance | Medium — fine at small scale | Medium | After P3 |
| 5 — Observability | Medium — hard to debug without it | Low | After P4 |
| 6 — Multi-Tenancy | Low — single-tenant is fine to start | High | Later |
| 7 — Self-Healing | Low — nice-to-have | High | Later |
| 8 — Community | Low — ship working product first | Medium | Last |
