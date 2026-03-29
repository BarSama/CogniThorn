"""Expandable incident display card."""
import streamlit as st


def incident_card(incident: dict, on_heal=None):
    """Render a single incident as an expandable card."""
    action = incident.get("action_taken", "pass")
    color = "🔴" if action == "block" else "🟡"
    label = f"{color} [{action.upper()}] {incident.get('method')} {incident.get('path')}"

    with st.expander(label, expanded=False):
        col1, col2 = st.columns(2)
        col1.metric("Guard Score", f"{incident.get('guard_score', 0):.2f}")
        col2.metric("Confidence", f"{incident.get('confidence', 0) or 0:.0%}")

        if incident.get("explanation"):
            st.info(f"🤖 **AI Verdict:** {incident['explanation']}")

        if incident.get("attack_type"):
            st.code(f"Attack Type: {incident['attack_type']}\nAffected: {incident.get('affected_parameter', 'unknown')}")

        if incident.get("remediation_hint"):
            st.warning(f"💡 **Fix:** {incident['remediation_hint']}")

        if incident.get("pr_url"):
            st.success(f"✅ [View Self-Healing PR]({incident['pr_url']})")
        elif action == "block" and on_heal:
            if st.button("🔧 Fix It", key=f"heal_{incident.get('id')}"):
                on_heal(incident.get("id"))
