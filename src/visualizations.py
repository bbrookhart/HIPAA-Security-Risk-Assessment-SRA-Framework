"""
src/visualizations.py
----------------------
Plotly chart builders for the HIPAA SRA Framework dashboard.

All charts follow a consistent healthcare-professional design system.
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

PALETTE = {
    "critical": "#EF4444",
    "high": "#F97316",
    "moderate": "#F59E0B",
    "low": "#22C55E",
    "primary": "#0EA5E9",
    "secondary": "#6366F1",
    "bg": "#FFFFFF",
    "muted": "#94A3B8",
    "text": "#1E293B",
    "border": "#E2E8F0",
}

TIER_COLORS = {
    "Critical": PALETTE["critical"],
    "High": PALETTE["high"],
    "Moderate": PALETTE["moderate"],
    "Low": PALETTE["low"],
}

BASE_LAYOUT = dict(
    font=dict(family="Inter, system-ui, sans-serif", size=13, color=PALETTE["text"]),
    plot_bgcolor=PALETTE["bg"],
    paper_bgcolor=PALETTE["bg"],
    margin=dict(l=10, r=10, t=50, b=10),
    hoverlabel=dict(bgcolor="white", bordercolor=PALETTE["muted"], font_size=12),
)


def _apply_base(fig, title="", height=400):
    fig.update_layout(
        **BASE_LAYOUT,
        title=dict(text=title, font=dict(size=15, weight="bold"), x=0.01),
        height=height,
    )
    return fig


def plot_compliance_gauge(compliance_score: float) -> go.Figure:
    """Gauge showing overall compliance posture (0–100)."""
    if compliance_score >= 80:
        bar_color = PALETTE["low"]
    elif compliance_score >= 60:
        bar_color = PALETTE["moderate"]
    elif compliance_score >= 40:
        bar_color = PALETTE["high"]
    else:
        bar_color = PALETTE["critical"]

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=compliance_score,
        number={"suffix": "/100", "font": {"size": 32, "color": bar_color}},
        title={"text": "Security Posture Score", "font": {"size": 14}},
        delta={"reference": 70, "increasing": {"color": PALETTE["low"]},
               "decreasing": {"color": PALETTE["critical"]}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": PALETTE["muted"]},
            "bar": {"color": bar_color, "thickness": 0.3},
            "bgcolor": "#F8FAFC",
            "borderwidth": 1,
            "bordercolor": PALETTE["border"],
            "steps": [
                {"range": [0, 40], "color": "#FEE2E2"},
                {"range": [40, 60], "color": "#FEF3C7"},
                {"range": [60, 80], "color": "#FEF9C3"},
                {"range": [80, 100], "color": "#DCFCE7"},
            ],
            "threshold": {
                "line": {"color": PALETTE["text"], "width": 3},
                "thickness": 0.75,
                "value": 70,
            },
        },
    ))
    fig.update_layout(**BASE_LAYOUT, height=280, margin=dict(l=30, r=30, t=40, b=10))
    return fig


def plot_risk_heatmap(register_data: list[dict]) -> go.Figure:
    """
    Likelihood vs. Impact scatter matrix — the classic risk heatmap.
    Each point is a HIPAA control. Color = risk tier.
    """
    if not register_data:
        return go.Figure()

    df = pd.DataFrame(register_data)

    # Add jitter to prevent perfect overlap
    import numpy as np
    rng = np.random.default_rng(42)
    df["jitter_x"] = df["Likelihood"].astype(float) + rng.uniform(-0.15, 0.15, len(df))
    df["jitter_y"] = df["Impact"].astype(float) + rng.uniform(-0.15, 0.15, len(df))

    color_map = {t: c for t, c in TIER_COLORS.items()}
    df["color"] = df["Risk Tier"].map(color_map).fillna(PALETTE["muted"])

    fig = go.Figure()

    for tier, color in TIER_COLORS.items():
        subset = df[df["Risk Tier"] == tier]
        if subset.empty:
            continue
        fig.add_trace(go.Scatter(
            x=subset["jitter_x"],
            y=subset["jitter_y"],
            mode="markers",
            name=tier,
            marker=dict(color=color, size=10, opacity=0.8,
                        line=dict(color="white", width=1)),
            hovertemplate=(
                "<b>%{customdata[0]}</b><br>"
                "%{customdata[1]}<br>"
                "Likelihood: %{customdata[2]} | Impact: %{customdata[3]}<br>"
                "Residual Risk: %{customdata[4]:.1f}<br>"
                "Tier: " + tier + "<extra></extra>"
            ),
            customdata=subset[[
                "Control ID", "Specification", "Likelihood", "Impact", "Residual Risk"
            ]].values,
        ))

    # Risk zone shading
    for (x0, y0, x1, y1, color, label) in [
        (0.5, 0.5, 2.5, 2.5, "rgba(34,197,94,0.06)", "Low Zone"),
        (0.5, 2.5, 2.5, 5.5, "rgba(245,158,11,0.06)", ""),
        (2.5, 0.5, 5.5, 2.5, "rgba(245,158,11,0.06)", ""),
        (2.5, 2.5, 5.5, 5.5, "rgba(239,68,68,0.08)", "High/Critical Zone"),
    ]:
        fig.add_shape(type="rect", x0=x0, y0=y0, x1=x1, y1=y1,
                      fillcolor=color, line_width=0, layer="below")

    fig.update_xaxes(
        title_text="Likelihood of Threat Occurrence (1=Very Low, 5=Very High)",
        range=[0.3, 5.7], dtick=1, showgrid=True, gridcolor=PALETTE["border"],
        tickvals=[1, 2, 3, 4, 5],
        ticktext=["1 Very Low", "2 Low", "3 Medium", "4 High", "5 Very High"],
    )
    fig.update_yaxes(
        title_text="Impact if Breach Occurs (1=Very Low, 5=Very High)",
        range=[0.3, 5.7], dtick=1, showgrid=True, gridcolor=PALETTE["border"],
        tickvals=[1, 2, 3, 4, 5],
        ticktext=["1 Very Low", "2 Low", "3 Medium", "4 High", "5 Very High"],
    )

    _apply_base(fig, "Risk Heat Map — Likelihood × Impact (Residual Risk by Control)", height=500)
    fig.update_layout(legend=dict(orientation="h", y=-0.18, x=0.0))
    return fig


def plot_domain_radar(domain_scores: dict) -> go.Figure:
    """Radar chart showing residual risk % by security domain."""
    if not domain_scores:
        return go.Figure()

    domains = list(domain_scores.keys())
    values = [domain_scores[d]["residual_pct"] for d in domains]
    domains_closed = domains + [domains[0]]
    values_closed = values + [values[0]]

    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=values_closed,
        theta=domains_closed,
        fill="toself",
        fillcolor="rgba(239,68,68,0.12)",
        line=dict(color=PALETTE["critical"], width=2),
        name="Residual Risk %",
        hovertemplate="<b>%{theta}</b><br>Risk: %{r:.1f}%<extra></extra>",
    ))

    # Target line at 20% (acceptable residual risk threshold)
    target_values = [20] * len(domains)
    target_closed = target_values + [target_values[0]]
    fig.add_trace(go.Scatterpolar(
        r=target_closed,
        theta=domains_closed,
        mode="lines",
        line=dict(color=PALETTE["low"], width=1.5, dash="dot"),
        name="Target Threshold (20%)",
        hovertemplate="Target: %{r}%<extra></extra>",
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 100], ticksuffix="%",
                            gridcolor=PALETTE["border"]),
            angularaxis=dict(gridcolor=PALETTE["border"]),
            bgcolor=PALETTE["bg"],
        ),
        legend=dict(orientation="h", y=-0.15),
        **BASE_LAYOUT,
        height=480,
        title=dict(text="Risk Exposure by Security Domain", font=dict(size=15, weight="bold"), x=0.01),
    )
    return fig


def plot_safeguard_bars(safeguard_scores: dict) -> go.Figure:
    """Bar chart comparing residual risk % and avg maturity across the 3 safeguard categories."""
    if not safeguard_scores:
        return go.Figure()

    safeguards = list(safeguard_scores.keys())
    residual_pcts = [safeguard_scores[s]["residual_pct"] for s in safeguards]
    avg_maturities = [safeguard_scores[s]["avg_maturity"] * 20 for s in safeguards]  # scale to 100

    colors = [
        PALETTE["critical"] if p >= 60 else
        PALETTE["high"] if p >= 40 else
        PALETTE["moderate"] if p >= 20 else
        PALETTE["low"]
        for p in residual_pcts
    ]

    fig = make_subplots(rows=1, cols=2,
                        subplot_titles=("Residual Risk %", "Avg Control Maturity (0–100)"),
                        horizontal_spacing=0.15)

    fig.add_trace(go.Bar(
        x=safeguards, y=residual_pcts, marker_color=colors,
        hovertemplate="<b>%{x}</b><br>Residual Risk: %{y:.1f}%<extra></extra>",
        name="Residual Risk",
    ), row=1, col=1)

    fig.add_trace(go.Bar(
        x=safeguards, y=avg_maturities, marker_color=PALETTE["primary"],
        hovertemplate="<b>%{x}</b><br>Avg Maturity: %{y:.0f}/100<extra></extra>",
        name="Avg Maturity",
    ), row=1, col=2)

    fig.update_yaxes(ticksuffix="%", gridcolor=PALETTE["border"], row=1, col=1)
    fig.update_yaxes(range=[0, 100], gridcolor=PALETTE["border"], row=1, col=2)
    fig.update_xaxes(showgrid=False)
    _apply_base(fig, "Performance by Safeguard Category", height=360)
    fig.update_layout(showlegend=False)
    return fig


def plot_tier_breakdown(tier_counts: dict) -> go.Figure:
    """Stacked bar showing count of controls in each risk tier."""
    tiers = ["Critical", "High", "Moderate", "Low"]
    counts = [tier_counts.get(t, 0) for t in tiers]
    colors = [TIER_COLORS[t] for t in tiers]

    fig = go.Figure(go.Bar(
        x=counts,
        y=["Controls"],
        orientation="h",
        marker_color=colors,
        text=[f"{t}: {c}" for t, c in zip(tiers, counts)],
        textposition="inside",
        hovertemplate="<b>%{text}</b><extra></extra>",
    ))

    # Actually render as separate bars for clarity
    fig = go.Figure()
    for tier, count, color in zip(tiers, counts, colors):
        fig.add_trace(go.Bar(
            name=tier,
            x=[count],
            y=["Risk Distribution"],
            orientation="h",
            marker_color=color,
            text=f"{tier}: {count}",
            textposition="auto",
            hovertemplate=f"<b>{tier}</b><br>Controls: {count}<extra></extra>",
        ))

    fig.update_layout(
        barmode="stack",
        xaxis_title="Number of Controls",
        showlegend=True,
        legend=dict(orientation="h", y=1.15),
        **BASE_LAYOUT,
        height=180,
        title=dict(text="Controls by Risk Tier", font=dict(size=15, weight="bold"), x=0.01),
        margin=dict(l=10, r=10, t=55, b=10),
    )
    return fig


def plot_remediation_waterfall(plan: list[dict]) -> go.Figure:
    """Waterfall chart showing residual risk reduction as remediations are applied."""
    if not plan:
        return go.Figure()

    milestones = ["Immediate\n(0–30d)", "Short-Term\n(30–90d)", "Medium-Term\n(90–180d)", "Annual\n(180–365d)"]
    milestone_map = {
        "Immediate (0–30 days)": 0,
        "Short-Term (30–90 days)": 1,
        "Medium-Term (90–180 days)": 2,
        "Annual Plan (180–365 days)": 3,
    }

    # Compute risk reduction per milestone
    risk_by_milestone = [0.0] * 4
    for item in plan:
        idx = milestone_map.get(item.get("milestone", "Annual Plan (180–365 days)"), 3)
        # Approximate risk reduction if control reaches maturity 3
        risk_by_milestone[idx] += item.get("residual_risk", 0) * 0.6

    total_current = sum(item.get("residual_risk", 0) for item in plan)
    running = total_current
    x_labels = ["Current\nResidual Risk"] + milestones + ["Target\nRisk"]
    y_vals = [total_current] + [-r for r in risk_by_milestone] + [0]
    measures = ["absolute"] + ["relative"] * 4 + ["total"]
    colors = [PALETTE["critical"]] + [PALETTE["primary"]] * 4 + [PALETTE["low"]]

    fig = go.Figure(go.Waterfall(
        name="Risk Reduction",
        orientation="v",
        measure=measures,
        x=x_labels,
        y=y_vals,
        textposition="outside",
        text=[f"{abs(v):.0f}" for v in y_vals],
        connector={"line": {"color": PALETTE["border"]}},
        increasing={"marker": {"color": PALETTE["critical"]}},
        decreasing={"marker": {"color": PALETTE["low"]}},
        totals={"marker": {"color": PALETTE["low"]}},
    ))

    _apply_base(fig, "Projected Risk Reduction by Remediation Milestone", height=420)
    fig.update_yaxes(title_text="Aggregate Residual Risk Score", gridcolor=PALETTE["border"])
    fig.update_xaxes(showgrid=False)
    return fig


def plot_maturity_distribution(register_data: list[dict]) -> go.Figure:
    """Bar chart showing distribution of control maturity scores."""
    if not register_data:
        return go.Figure()

    df = pd.DataFrame(register_data)
    counts = df["Maturity Score"].value_counts().sort_index()

    maturity_labels = {
        0: "0 – Not Implemented",
        1: "1 – Initial",
        2: "2 – Developing",
        3: "3 – Defined",
        4: "4 – Managed",
        5: "5 – Optimizing",
    }
    maturity_colors = {
        0: PALETTE["critical"],
        1: PALETTE["high"],
        2: PALETTE["moderate"],
        3: "#84CC16",
        4: PALETTE["low"],
        5: "#059669",
    }

    fig = go.Figure(go.Bar(
        x=[maturity_labels.get(k, str(k)) for k in counts.index],
        y=counts.values,
        marker_color=[maturity_colors.get(k, PALETTE["muted"]) for k in counts.index],
        hovertemplate="<b>%{x}</b><br>Controls: %{y}<extra></extra>",
        text=counts.values,
        textposition="auto",
    ))

    _apply_base(fig, "Control Maturity Distribution Across All HIPAA Specifications", height=360)
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridcolor=PALETTE["border"], title_text="Number of Controls")
    return fig
