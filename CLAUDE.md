# CogniThorn — Project Guide

---

## How Claude Works With You On This Project

> **This is a learning project.** The rules below are always active.

1. **Explain before acting.** Before writing or changing any code, Claude must explain *why* that approach was chosen — what problem it solves, what alternatives exist, and what trade-offs were made.

2. **Teach the concept, not just the code.** Every non-trivial decision (e.g. "why Redis instead of a DB table?", "why run ONNX in a thread pool?") gets a plain-English explanation as if you've never seen a WAF before.

3. **Flag blind spots proactively.** If something could go wrong, has a hidden assumption, or is a common beginner pitfall in security/distributed systems, Claude must surface it — even if it wasn't asked.

4. **Show how to investigate.** When debugging, Claude must walk through *how* to find the problem (which logs to read, which command to run, what to look for) — not just hand over the fix.

5. **No silent changes.** Every file edit includes a one-line "what changed and why" note. No code is modified without explaining the reasoning out loud first.

6. **Encourage questions.** At the end of any significant explanation, Claude should prompt: *"Does this make sense? Anything you'd like me to go deeper on?"*

---

## What Is CogniThorn?
CogniThorn is an open-source AI-native Web Application Firewall (WAF). Instead of static rules like "block anything containing 'SELECT'", it uses machine learning to understand *intent*. When it detects an attack, it tells you in plain English what happened — and can even open a GitHub PR to fix the vulnerable code automatically (Self-Healing).

**The pitch:** Enterprise-grade security at $0 cloud cost. Fully self-hosted, one Docker Compose command.

---

## Architecture in Plain English

Think of it as two teams:

| Plane | Role | Analogy |
|---|---|---|
| **SSL Gateway** | The front door — terminates HTTPS, routes to WAF workers | Bouncer at the entrance |
| **Data Plane** (WAF Workers) | The actual security inspection — AI scoring, blocking, forwarding | Security guards inside |
| **Control Plane** | Management office — dashboard, settings, health checks | Security manager's office |

### How a Request Flows
```
Browser → SSL Gateway :443
  → SNI lookup (which domain?) → get upstream from Redis
  → pick a healthy WAF worker (round-robin from Redis)
  → WAF Worker :9000
      → ONNX model scores request (Fast Path, <15ms)
          score < 0.7 → forward to your upstream app ✓
          score ≥ 0.7 → check Redis cache for known attack hash
                          cache hit  → use cached verdict (instant)
                          cache miss → ask Gemini Flash for verdict
                              is_attack=false → forward (false positive) ✓
                              is_attack=true  → block 403 + log incident ✗
                                               → (optional) open GitHub PR
  → Response back to browser
```

### What "Fail-Open" Means
If the ONNX model crashes or Gemini times out, **CogniThorn passes the request through** and logs a `CRITICAL` warning. Security tools must never accidentally become denial-of-service tools.

---

## Folder Structure

```
CogniThorn/
├── ssl_gateway/      The front door — TLS termination + L7 load balancer
├── data_plane/       WAF worker — ONNX inference + Gemini + proxy logic
├── control_plane/    Management — API, dashboard, self-healing, worker registry
├── shared/           Python library shared by data_plane and control_plane
├── scripts/          One-time ops: migrate DB, seed settings, download ML model
├── models/           ONNX model files (gitignored, download separately)
└── docker-compose.yml  Entire stack in one file
```

---

## Key Concepts (Each in 2 Sentences)

**ONNX Runtime:** A way to run machine learning models without heavy frameworks like PyTorch. The model is pre-trained, exported to the ONNX format, and runs inference in ~15ms on a plain CPU.

**Redis Pub/Sub:** A messaging pattern where one process publishes a message to a channel and all subscribers receive it instantly. CogniThorn uses it so the dashboard can change the sensitivity threshold and all WAF workers update in under 100ms without restarting.

**PgBouncer:** A connection pooler that sits in front of PostgreSQL. Each WAF worker opens a connection to PgBouncer (not Postgres directly), and PgBouncer reuses a small pool of real DB connections — prevents overwhelming Postgres under high load.

**pg_auto_failover:** A PostgreSQL extension that monitors a primary+standby pair and automatically promotes the standby if the primary goes down (within ~30s). No manual intervention needed.

**Redis Sentinel:** A Redis HA mode with 3 nodes: a master, a replica, and a sentinel process. The sentinel monitors and automatically promotes the replica if the master dies (within ~10s).

**SNI (Server Name Indication):** A TLS extension where the browser tells the server *which domain* it's connecting to before the TLS handshake completes. Our SSL Gateway uses this to serve the correct certificate per domain without needing separate IPs.

**ACME / Let's Encrypt:** A protocol for automatically issuing and renewing free SSL certificates. Our SSL Gateway implements the ACME HTTP-01 challenge: Let's Encrypt makes an HTTP request to `/.well-known/acme-challenge/{token}` to verify domain ownership.

**Leader Election:** When 2 control-plane replicas are running, only one should process GitHub PRs (to avoid duplicate PRs). We use `Redis SETNX` (Set if Not eXists) as a distributed lock — whichever replica grabs the key first becomes the leader.

---

## Common Commands

```bash
# Start the full stack (2 WAF workers by default)
docker compose up -d

# Scale WAF workers to 5
docker compose up -d --scale waf-worker=5

# View live logs from WAF workers
docker compose logs -f waf-worker

# Run DB migrations (after pulling new code)
docker compose exec control-plane python scripts/migrate_db.py

# Download the ONNX model (required before first run)
docker compose run --rm waf-worker python scripts/download_model.py

# Reset everything (wipes DB — careful!)
docker compose down -v && docker compose up -d

# Run tests
docker compose exec waf-worker pytest tests/ -v

# Check worker registry
curl http://localhost:8090/api/workers

# Test attack detection (HTTP — SSL Gateway port 80)
curl -X POST http://localhost/login \
  -H "Host: app.example.com" \
  -d "username=admin' OR '1'='1"
```

---

## Environment Variables (`.env`)

| Variable | Required | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Google Gemini 1.5 Flash API key (free tier: 15 RPM) |
| `UPSTREAM_URL` | Yes | Default upstream app (e.g. `http://myapp:3000`) |
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password |
| `GITHUB_TOKEN` | No | For Self-Healing PR creation |
| `GITHUB_REPO` | No | `owner/repo` format |
| `SENSITIVITY_THRESHOLD` | No | Guard score cutoff, default `0.7` |

---

## Development Status

- [x] `shared/` — base package (DB models, settings, schemas)
- [x] `data_plane/` — WAF proxy + ONNX guard + Gemini analyst
- [x] `control_plane/` — API + registry + dashboard + healing
- [x] `ssl_gateway/` — TLS termination + ACME + worker routing
- [x] `docker-compose.yml` — full HA stack
- [x] `README.md`
- [ ] Tests
- [ ] End-to-end smoke test with a real upstream app

---

## Ports Reference

| Port | Service | Access |
|---|---|---|
| 80 | SSL Gateway (HTTP + ACME challenges) | Public |
| 443 | SSL Gateway (HTTPS) | Public |
| 8090 | Control Plane Management API | Internal |
| 8501 | Streamlit Dashboard | Internal (expose as needed) |
| 9000 | WAF Worker | Internal only |
| 5432 | PgBouncer → PostgreSQL | Internal |
| 6379 | Redis master | Internal |
