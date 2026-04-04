"""Configuration: sensitivity, API keys, worker status."""
import streamlit as st
import httpx
import os

st.header("⚙️ Configuration")

API_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8090")
_HEADERS = {"X-API-Key": os.getenv("CONTROL_PLANE_API_KEY", "")}


@st.cache_data(ttl=5)
def fetch_settings():
    try:
        resp = httpx.get(f"{API_URL}/api/settings", headers=_HEADERS, timeout=5)
        return resp.json()
    except Exception:
        return {}


@st.cache_data(ttl=5)
def fetch_workers():
    try:
        resp = httpx.get(f"{API_URL}/api/workers", headers=_HEADERS, timeout=5)
        return resp.json()
    except Exception:
        return []


current = fetch_settings()

st.subheader("Detection Settings")
threshold = st.slider(
    "Sensitivity Threshold",
    min_value=0.0, max_value=1.0, step=0.05,
    value=float(current.get("sensitivity_threshold", 0.7)),
    help="Guard score cutoff. Lower = more sensitive (more false positives). Higher = more relaxed.",
)

healing = st.toggle("Enable Self-Healing (GitHub PRs)", value=current.get("enable_self_healing") == "true")

if st.button("Save Settings"):
    try:
        resp = httpx.put(f"{API_URL}/api/settings", json={
            "sensitivity_threshold": str(threshold),
            "enable_self_healing": str(healing).lower(),
        }, headers=_HEADERS, timeout=5)
        st.success("Settings saved and broadcast to all workers.")
        st.cache_data.clear()
    except Exception as e:
        st.error(str(e))

st.subheader("API Keys")
with st.form("api_keys"):
    gemini_key = st.text_input("Gemini API Key", type="password", placeholder="AIza...")
    github_token = st.text_input("GitHub Token", type="password", placeholder="ghp_...")
    github_repo = st.text_input("GitHub Repo", placeholder="owner/repo")
    if st.form_submit_button("Save Keys"):
        updates = {}
        if gemini_key:
            updates["gemini_api_key"] = gemini_key
        if github_token:
            updates["github_token"] = github_token
        if github_repo:
            updates["github_repo"] = github_repo
        if updates:
            httpx.put(f"{API_URL}/api/settings", json=updates,
                      headers=_HEADERS, timeout=5)
            st.success("Keys saved.")

st.subheader("Active Workers")
workers = fetch_workers()
if workers:
    for w in workers:
        status = "🟢" if w.get("status") == "healthy" else "🔴"
        st.markdown(f"{status} **{w['id']}** — {w['host']}:{w['port']}")
else:
    st.warning("No workers registered.")
