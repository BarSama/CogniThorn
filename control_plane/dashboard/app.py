"""Streamlit dashboard entry point."""
import streamlit as st

st.set_page_config(
    page_title="CogniThorn WAF",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.sidebar.title("🛡️ CogniThorn")
st.sidebar.markdown("AI-Native Web Application Firewall")

# Show AI degraded warning if fail_open_count is elevated
import redis as _redis_sync
import os
try:
    r = _redis_sync.Redis.from_url(os.getenv("REDIS_URL", "redis://redis-master:6379"), decode_responses=True)
    fail_count = int(r.get("cognithhorn:stats:fail_open_count") or 0)
    if fail_count > 0:
        st.sidebar.error(f"⚠️ AI Degraded: {fail_count} fail-open events in last 10 min")
except Exception:
    pass

st.title("🛡️ CogniThorn Dashboard")
st.info("Use the sidebar to navigate between Monitor, Incidents, SSL Domains, and Configuration.")
