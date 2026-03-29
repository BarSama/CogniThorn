"""Install default settings rows. Called once on first boot."""
from shared.db.crud import upsert_setting

DEFAULT_SETTINGS = {
    "sensitivity_threshold": ("0.7", "Guard score cutoff for deep AI analysis (0.0-1.0)"),
    "enable_self_healing": ("false", "Auto-create GitHub PRs for confirmed attacks"),
    "max_body_size_kb": ("64", "Max request body size to analyze (KB)"),
    "lb_strategy": ("round_robin", "Load balancing strategy: round_robin or least_connections"),
    "gemini_model": ("gemini-1.5-flash", "Gemini model name"),
    "analysis_cache_ttl": ("86400", "Gemini analysis cache TTL in seconds"),
    "fail_open_alert_threshold": ("5", "Consecutive AI failures before dashboard alert"),
}


async def seed_default_settings():
    for key, (value, _desc) in DEFAULT_SETTINGS.items():
        await upsert_setting(key, value)
