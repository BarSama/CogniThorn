"""Incident Lab: browse blocked requests and trigger self-healing."""
import streamlit as st
import httpx
import os

st.header("🕵️ Incident Lab")

API_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8090")


@st.cache_data(ttl=5)
def fetch_incidents(attack_type=None):
    try:
        params = {"limit": 100}
        if attack_type:
            params["attack_type"] = attack_type
        resp = httpx.get(f"{API_URL}/api/incidents", params=params, timeout=5)
        return resp.json()
    except Exception as e:
        st.error(f"Failed to fetch incidents: {e}")
        return []


def heal_incident(incident_id: int):
    try:
        resp = httpx.post(f"{API_URL}/api/incidents/{incident_id}/heal", timeout=5)
        if resp.status_code == 200:
            st.success("Self-healing triggered! A GitHub PR will be created shortly.")
        else:
            st.error(f"Healing failed: {resp.text}")
    except Exception as e:
        st.error(f"Error: {e}")


attack_filter = st.selectbox("Filter by attack type", ["all", "sqli", "xss", "path_traversal", "rce"])
incidents = fetch_incidents(attack_filter if attack_filter != "all" else None)

if not incidents:
    st.info("No blocked incidents yet.")
else:
    st.caption(f"Showing {len(incidents)} incidents")
    from control_plane.dashboard.components.incident_card import incident_card
    for inc in incidents:
        incident_card(inc, on_heal=heal_incident)
