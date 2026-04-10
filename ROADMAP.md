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

- [x] **API Authentication:** `X-API-Key` middleware on all `/api/*` routes (`control_plane/api/auth.py`). Key set via `CONTROL_PLANE_API_KEY` env var; skipped with warning if unset (dev-safe).
- [ ] **Rate-limit the management API:** Prevent brute-force or flood attacks on `/api/*`
- [ ] **Secrets management:** Move API keys out of the DB (plaintext) into env vars or a vault
- [x] **Input validation on domains:** SSRF protection via `DomainCreate.block_ssrf` Pydantic validator — rejects private IP ranges and `localhost` in `upstream_url`. *(Known gap: DNS rebinding — tracked for Phase 4)*
- [ ] **TLS for internal services:** Currently workers talk to PostgreSQL and Redis over plain TCP inside Docker. Fine for single-host; add TLS for multi-host deployments.
- [x] **`key_pem` encryption at rest:** Fernet AES-128-CBC encryption via `shared/crypto.py`. Key set via `KEY_ENCRYPTION_SECRET` env var. `ENC:` prefix distinguishes encrypted from legacy plaintext rows.
- [x] **Audit log:** `audit_log` table + `write_audit_log()` CRUD. All mutations (settings change, domain add, worker register/deregister, healing triggered) write actor IP + old/new values. Exposed at `GET /api/audit`.

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

- [x] **Benchmark dataset:** `tests/data/payloads.json` — 65 labeled samples: 15 SQLi (incl. 5 obfuscated), 12 XSS, 8 path traversal, 6 RCE, 14 clean, 10 tricky-clean (false-positive traps)
- [x] **Benchmark script:** `scripts/benchmark_model.py` — per-attack-type TP/FP breakdown, precision/recall/F1, P50/P95/P99 latency, wrong-prediction list with recommendations
- [x] **Threshold calibration:** `scripts/calibrate_threshold.py` — sweeps 0.05→0.95, prints full precision/recall/F1 table, highlights best-F1 threshold vs current, warns if attacks score below threshold
- [x] **Fine-tune pipeline:** `scripts/fine_tune_model.py` — stratified train/eval split, HuggingFace Trainer, exports to ONNX via optimum. Fallback path for CPU-only environments.
- [x] **Tokenizer tests:** `tests/test_tokenizer.py` — 7 tests verifying injection chars preserved, body truncated at 512, Unicode safety, format stability, different payloads produce different inputs
- [x] **Model selection documented:** `scripts/download_model.py` — documents distilbert-base-uncased vs jackaduma/SecBERT trade-offs with production recommendation
- [ ] **Run benchmark** (requires Docker + downloaded model): `docker compose exec waf-worker python scripts/benchmark_model.py`
- [ ] **Run calibration** (requires Docker + downloaded model): `docker compose exec waf-worker python scripts/calibrate_threshold.py`
- [ ] **Fine-tune and re-benchmark** if F1 < 0.85

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

- [x] **Latency profiling script:** `scripts/load_test.py` (locust) — 80% clean / 15% attack / 5% edge case mix; auto-marks 403s as success; reports P50/P95/P99 on test stop. *(Run with Docker: `locust -f scripts/load_test.py --host http://localhost`)*
- [x] **ONNX model quantization:** `scripts/quantize_model.py` — INT8 dynamic quantization; reduces model ~75% in size, ~40% faster inference; verifies score delta < 0.05 after conversion. *(Run after downloading model)*
- [ ] **Connection pool tuning:** Benchmark PgBouncer pool_size vs worker count *(requires live stack)*
- [x] **Redis pipeline:** Counter increments in `middleware.py` now use `pipeline(transaction=False)` — both `requests_total` and the type-specific counter sent in one round-trip. Applies to both clean and blocked paths.
- [x] **Graceful shutdown:** `main.py` shutdown hook marks worker as `"draining"` in Redis (SSL Gateway stops routing within ~100ms), sleeps 8s drain window, then deregisters. Prevents 502s during `docker compose restart`.
- [x] **Circuit breaker for Gemini:** `analyst.py` — `_CircuitBreaker` dataclass tracks consecutive 5xx failures. After 3 strikes: OPEN (fail-open for 60s). After 60s: HALF-OPEN (one trial). On success: CLOSED. 429 rate-limit errors are NOT counted (Gemini is up, just busy). *Note: per-worker state; use Redis for multi-worker coordination.*

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
