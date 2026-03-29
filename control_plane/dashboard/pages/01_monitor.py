"""Real-Time Monitor: traffic stats and threat gauge."""
import time
import streamlit as st
import redis as _redis
import os

st.header("🛡️ Real-Time Monitor")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-master:6379")


def get_stats():
    try:
        r = _redis.Redis.from_url(REDIS_URL, decode_responses=True)
        total = int(r.get("cognithhorn:stats:requests_total") or 0)
        blocked = int(r.get("cognithhorn:stats:requests_blocked") or 0)
        clean = int(r.get("cognithhorn:stats:requests_clean") or 0)
        fp = int(r.get("cognithhorn:stats:false_positives_total") or 0)
        blocked_pct = (blocked / total * 100) if total > 0 else 0
        return {"total": total, "blocked": blocked, "clean": clean, "fp": fp, "blocked_pct": blocked_pct}
    except Exception as e:
        return {"total": 0, "blocked": 0, "clean": 0, "fp": 0, "blocked_pct": 0, "error": str(e)}


placeholder = st.empty()

for _ in range(9999):
    stats = get_stats()
    with placeholder.container():
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests", stats["total"])
        col2.metric("Blocked", stats["blocked"])
        col3.metric("Clean", stats["clean"])
        col4.metric("False Positives", stats["fp"])

        from control_plane.dashboard.components.threat_gauge import threat_gauge
        st.plotly_chart(threat_gauge(stats["blocked_pct"]), use_container_width=True)

        if stats.get("error"):
            st.error(f"Redis error: {stats['error']}")

    time.sleep(2)
