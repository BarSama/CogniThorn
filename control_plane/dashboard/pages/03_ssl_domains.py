"""SSL & Domains: manage domains and certificates."""
import streamlit as st
import httpx
import os

st.header("🔐 SSL & Domains")
st.caption("Add domains to protect. CogniThorn will auto-issue Let's Encrypt certificates.")

API_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8090")
_HEADERS = {"X-API-Key": os.getenv("CONTROL_PLANE_API_KEY", "")}


@st.cache_data(ttl=10)
def fetch_domains():
    try:
        resp = httpx.get(f"{API_URL}/api/domains", headers=_HEADERS, timeout=5)
        return resp.json()
    except Exception as e:
        return []


with st.form("add_domain"):
    st.subheader("Add Domain")
    fqdn = st.text_input("Domain (FQDN)", placeholder="app.example.com")
    upstream = st.text_input("Upstream URL", placeholder="http://myapp:3000")
    submitted = st.form_submit_button("Add & Issue Certificate")
    if submitted and fqdn and upstream:
        try:
            resp = httpx.post(
                f"{API_URL}/api/domains",
                json={"fqdn": fqdn, "upstream_url": upstream},
                headers=_HEADERS, timeout=10,
            )
            if resp.status_code == 200:
                st.success(f"Domain {fqdn} added. Certificate issuance in progress...")
                st.cache_data.clear()
            else:
                st.error(resp.text)
        except Exception as e:
            st.error(str(e))

st.subheader("Configured Domains")
domains = fetch_domains()
if not domains:
    st.info("No domains configured yet.")
for d in domains:
    status_icon = "✅" if d.get("acme_status") == "issued" else "⏳"
    exp = d.get("expires_at", "N/A")
    st.markdown(f"**{status_icon} {d['fqdn']}** → `{d['upstream_url']}` | Cert expires: `{exp}`")
