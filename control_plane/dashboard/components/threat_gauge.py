"""Plotly threat level gauge widget."""
import plotly.graph_objects as go


def threat_gauge(blocked_pct: float) -> go.Figure:
    """
    blocked_pct: 0-100, percentage of recent requests that were blocked.
    """
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=blocked_pct,
        title={"text": "Threat Level"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "darkred"},
            "steps": [
                {"range": [0, 5], "color": "#00cc44"},
                {"range": [5, 20], "color": "#ffcc00"},
                {"range": [20, 100], "color": "#cc0000"},
            ],
            "threshold": {
                "line": {"color": "white", "width": 4},
                "thickness": 0.75,
                "value": blocked_pct,
            },
        },
        number={"suffix": "%", "font": {"size": 28}},
    ))
    fig.update_layout(height=250, margin=dict(t=40, b=10, l=10, r=10))
    return fig
