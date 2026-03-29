# 🛡️ CogniThorn — AI-Native Web Application Firewall

CogniThorn is an open-source WAF that replaces static rules with adaptive AI. It explains attacks in plain English and can automatically open GitHub PRs to fix the underlying vulnerability in your code.

**$0 cloud cost. Fully self-hosted. One Docker Compose command.**

---

## Architecture

```
DNS ──► Your Server IP
            │
     ┌──────▼──────┐
     │ SSL Gateway  │  Port 80 (ACME) + 443 (HTTPS)
     │ Built by us  │  Auto-issues Let's Encrypt certs
     └──────┬──────┘  Reads Redis → routes direct to workers
            │
  ┌─────────┴──────────┐
  │ WAF Worker(s) :9000 │  Scale freely with --scale
  │ ONNX <15ms guard    │
  │ Gemini deep analysis│
  │ Redis cache         │
  └─────────┬──────────┘
            │
     ┌──────▼──────┐
     │  PostgreSQL  │  HA via pg_auto_failover
     │  PgBouncer   │  Connection pooling
     │  Redis HA    │  Sentinel: master + replica + sentinel
     └─────────────┘

Control Plane :8090/:8501   (management only, NOT in hot path)
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/barsama/cognithorn
cd cognithorn
cp .env.example .env
# Edit .env — set GEMINI_API_KEY and UPSTREAM_URL at minimum
```

### 2. Download the ONNX model

```bash
docker compose run --rm waf-worker python scripts/download_model.py
```

### 3. Start the stack

```bash
docker compose up -d
```

### 4. Add your domain

```bash
# Via API
curl -X POST http://localhost:8090/api/domains \
  -H "Content-Type: application/json" \
  -d '{"fqdn": "app.example.com", "upstream_url": "http://your-app:3000"}'

# Or via the dashboard
open http://localhost:8501
```

### 5. Point DNS to your server

```
app.example.com  CNAME  →  your-server-hostname
# or
app.example.com  A      →  your-server-ip
```

CogniThorn auto-issues a Let's Encrypt certificate for your domain.

---

## Scaling

```bash
# Scale to 5 WAF workers
docker compose up -d --scale waf-worker=5

# Check registered workers
curl http://localhost:8090/api/workers
```

---

## Test Attack Detection

```bash
# SQL Injection (should return 403 with human-readable explanation)
curl -X POST http://localhost/login \
  -H "Host: app.example.com" \
  -d "username=admin' OR '1'='1"

# XSS (should return 403)
curl "http://localhost/search?q=<script>alert(1)</script>" \
  -H "Host: app.example.com"

# Clean traffic (should pass through)
curl http://localhost/ -H "Host: app.example.com"
```

---

## Self-Healing (Auto GitHub PRs)

When a real attack is confirmed, CogniThorn can open a GitHub PR to fix the vulnerable code:

1. Set `GITHUB_TOKEN` and `GITHUB_REPO` in `.env`
2. Enable self-healing in the dashboard (Configuration tab) or:
   ```bash
   curl -X PUT http://localhost:8090/api/settings \
     -H "Content-Type: application/json" \
     -d '{"enable_self_healing": "true"}'
   ```
3. Click "Fix It" on any blocked incident in the dashboard

---

## Dashboard

Open `http://localhost:8501` for:

| Tab | What you see |
|---|---|
| 🛡️ Real-Time Monitor | Live request counters + threat level gauge |
| 🕵️ Incident Lab | All blocked requests with AI explanations + "Fix It" button |
| 🔐 SSL & Domains | Add domains, view cert expiry, ACME status |
| ⚙️ Configuration | Sensitivity slider, API keys, worker status |

---

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GEMINI_API_KEY` | **Yes** | — | Google Gemini 1.5 Flash (free: 15 RPM) |
| `UPSTREAM_URL` | **Yes** | — | Default upstream app URL |
| `POSTGRES_PASSWORD` | **Yes** | — | PostgreSQL password |
| `GITHUB_TOKEN` | No | — | Self-healing PR creation |
| `GITHUB_REPO` | No | — | `owner/repo` for self-healing |
| `SENSITIVITY_THRESHOLD` | No | `0.7` | Guard score cutoff (0.0–1.0) |
| `ACME_EMAIL` | No | `admin@example.com` | Let's Encrypt notifications |

---

## Sizing Guide

| Tier | Server | Workers | Throughput |
|---|---|---|---|
| Dev / Indie | 2 vCPU / 4GB | 1 | ~30 req/s |
| Startup | 4 vCPU / 8GB | 2 | ~100 req/s |
| SaaS | 8 vCPU / 16GB | 4 | ~400 req/s |
| Enterprise | 16+ vCPU / 32GB | 8+ | 1000+ req/s |

**CPU bottleneck:** ONNX inference is ~15ms/request per core (~66 req/s). Scale workers horizontally.

---

## High Availability

The default `docker-compose.yml` provides:
- **PostgreSQL**: primary + streaming standby (`pg_auto_failover`, promotes in <30s)
- **Redis**: master + replica + sentinel (promotes in <10s)
- **WAF Workers**: N replicas, SSL Gateway routes around failures
- **SSL Gateway**: single container; for multi-host HA, put a floating IP (VRRP) in front

---

## How Detection Works

```
Request arrives
    ↓
ONNX DistilBERT scores it (Fast Path, <15ms)
    ↓ score < 0.7 → PASS immediately
    ↓ score ≥ 0.7
Check Redis cache (SHA-256 of payload)
    ↓ cache hit  → use cached Gemini verdict (instant, saves API quota)
    ↓ cache miss → call Gemini Flash (Deep Path)
                        → is_attack=false → PASS (false positive)
                        → is_attack=true  → BLOCK 403
                                             log to PostgreSQL
                                             (optional) open GitHub PR
```

**Fail-Open policy:** If ONNX crashes or Gemini times out, the request is passed through and a `CRITICAL` warning is logged. The dashboard shows a red "AI Degraded" banner. CogniThorn never becomes a denial-of-service tool.

---

## Project Structure

```
CogniThorn/
├── ssl_gateway/      Custom SSL termination + L7 routing (Python/asyncio)
├── data_plane/       WAF workers: ONNX + Gemini + proxy
├── control_plane/    Management API + Streamlit dashboard + self-healing
├── shared/           Pip package shared by data_plane and control_plane
├── scripts/          DB migrations, model download
├── models/           ONNX model (gitignored, run scripts/download_model.py)
└── docker-compose.yml
```

---

## License

MIT — see LICENSE file.
