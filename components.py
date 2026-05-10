"""
Reusable Streamlit UI components for the CyberGuard AI dashboard.
"""
 
import plotly.graph_objects as go
import streamlit as st
from typing import Dict, List, Tuple
 
 
# ─── Metric Cards ─────────────────────────────────────────────────────────────
 
def render_metric_card(label: str, value: str, icon: str, color: str, delta: str = ""):
    delta_html = (
        f'<div style="color:#64748b;font-size:0.75rem">{delta}</div>'
        if delta else ""
    )
    st.markdown(
        f"""
        <div style="background:linear-gradient(135deg,{color}22,{color}11);
             border:1px solid {color}55;border-radius:12px;padding:16px 20px;
             margin-bottom:8px;">
          <div style="font-size:1.6rem">{icon}</div>
          <div style="color:#aab4be;font-size:0.78rem;font-weight:600;
               letter-spacing:0.08em;margin:4px 0 2px">{label.upper()}</div>
          <div style="color:{color};font-size:1.6rem;font-weight:700;
               font-family:'Courier New',monospace">{value}</div>
          {delta_html}
        </div>
        """,
        unsafe_allow_html=True,
    )
 
 
# ─── Threat Badge ─────────────────────────────────────────────────────────────
 
def render_threat_badge(threat: str, severity: str, color: str):
    st.markdown(
        f"""
        <div style="background:linear-gradient(135deg,{color}33,{color}11);
             border:2px solid {color};border-radius:16px;padding:20px 28px;
             text-align:center;margin:12px 0;">
          <div style="font-size:3rem;margin-bottom:8px">⚠️</div>
          <div style="color:{color};font-size:1.9rem;font-weight:800;
               letter-spacing:0.04em">{threat}</div>
          <div style="color:#94a3b8;font-size:1rem;margin-top:6px">
            Severity: <span style="color:{color};font-weight:700">{severity}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
 
 
# ─── Probability Bar Chart ────────────────────────────────────────────────────
 
def render_probability_chart(probabilities: Dict[str, float]) -> go.Figure:
    labels = list(probabilities.keys())
    values = list(probabilities.values())
    max_val = max(values) if values else 0
    bar_colors = ["#D50000" if v == max_val else "#1565C0" for v in values]
 
    fig = go.Figure(go.Bar(
        x=values,
        y=labels,
        orientation="h",
        marker=dict(color=bar_colors, line=dict(width=0)),
        text=[f"{v:.1f}%" for v in values],
        textposition="outside",
    ))
    fig.update_layout(
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font=dict(color="#E2E8F0", size=12),
        margin=dict(l=10, r=60, t=10, b=10),
        xaxis=dict(
            range=[0, 110],
            showgrid=False,
            zeroline=False,
            showticklabels=False,
        ),
        yaxis=dict(showgrid=False),
        height=280,
    )
    return fig
 
 
# ─── Risk Gauge ───────────────────────────────────────────────────────────────
 
def render_risk_gauge(risk_score: int) -> go.Figure:
    if risk_score < 20:
        color = "#00C853"
    elif risk_score < 70:
        color = "#FF6D00"
    else:
        color = "#D50000"
 
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        number={"suffix": "/100", "font": {"size": 28, "color": color}},
        gauge=dict(
            axis=dict(range=[0, 100], tickcolor="#E2E8F0"),
            bar=dict(color=color, thickness=0.3),
            bgcolor="#1E293B",
            borderwidth=0,
            steps=[
                dict(range=[0,  30], color="#1B5E20"),
                dict(range=[30, 70], color="#E65100"),
                dict(range=[70, 100], color="#B71C1C"),
            ],
            threshold=dict(
                line=dict(color="white", width=3),
                thickness=0.8,
                value=risk_score,
            ),
        ),
        title={"text": "Risk Score", "font": {"color": "#94a3b8", "size": 14}},
    ))
    fig.update_layout(
        paper_bgcolor="#111827",
        font_color="#E2E8F0",
        margin=dict(l=20, r=20, t=40, b=10),
        height=230,
    )
    return fig
 
 
# ─── Confidence Donut ─────────────────────────────────────────────────────────
 
def render_confidence_donut(confidence: float, threat: str, color: str) -> go.Figure:
    fig = go.Figure(go.Pie(
        values=[confidence, 100 - confidence],
        labels=[threat, ""],
        hole=0.72,
        marker=dict(colors=[color, "#1E293B"]),
        textinfo="none",
        hoverinfo="skip",
    ))
    fig.add_annotation(
        text=f"<b>{confidence:.1f}%</b>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font=dict(size=22, color=color),
    )
    fig.update_layout(
        paper_bgcolor="#111827",
        showlegend=False,
        margin=dict(l=10, r=10, t=10, b=10),
        height=200,
    )
    return fig
 
 
# ─── Entity Tags ──────────────────────────────────────────────────────────────
 
def render_entity_tags(entities: Dict[str, List[str]]):
    labels = {
        "urls":   "🔗 URL",
        "ips":    "🖥 IP",
        "emails": "📧 Email",
        "cves":   "🛡 CVE",
        "hashes": "🔑 Hash",
    }
    colors = {
        "urls":   "#0D47A1",
        "ips":    "#1B5E20",
        "emails": "#4A148C",
        "cves":   "#B71C1C",
        "hashes": "#E65100",
    }
    found_any = False
    for key, label in labels.items():
        items = entities.get(key, [])
        if not items:
            continue
        found_any = True
        tags_html = " ".join([
            f'<span style="background:{colors[key]}33;'
            f'border:1px solid {colors[key]}88;'
            f'color:#E2E8F0;border-radius:6px;padding:3px 10px;'
            f'font-size:0.82rem;font-family:monospace">{item}</span>'
            for item in items[:6]
        ])
        st.markdown(f"**{label}:** {tags_html}", unsafe_allow_html=True)
        st.markdown("")
    if not found_any:
        st.info("No specific cyber entities detected.")
 
 
# ─── Keyword Pills ────────────────────────────────────────────────────────────
 
def render_keyword_pills(top_keywords: List[Tuple[str, str]]):
    cat_colors = {
        "phishing":      "#0D47A1",
        "malware":       "#B71C1C",
        "ransomware":    "#4E342E",
        "ddos":          "#E65100",
        "sql_injection": "#1B5E20",
        "benign":        "#37474F",
    }
    if not top_keywords:
        st.info("No threat-specific keywords found.")
        return
 
    pills_html = " ".join([
        f'<span style="background:{cat_colors.get(cat, "#333")}55;'
        f'border:1px solid {cat_colors.get(cat, "#666")}99;'
        f'color:#E2E8F0;border-radius:20px;padding:4px 12px;'
        f'font-size:0.82rem;display:inline-block;margin:3px">{kw}</span>'
        for kw, cat in top_keywords
    ])
    st.markdown(pills_html, unsafe_allow_html=True)
 
 
# ─── Reasoning Cards ──────────────────────────────────────────────────────────
 
def render_reasoning(reasoning: List[str], color: str):
    for i, reason in enumerate(reasoning, 1):
        st.markdown(
            f"""
            <div style="background:#1E293B;border-left:4px solid {color};
                 border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:8px;">
              <span style="color:{color};font-weight:700">#{i}</span>
              <span style="color:#CBD5E1;margin-left:8px">{reason}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
 
 
# ─── Recommendations ──────────────────────────────────────────────────────────
 
def render_recommendations(recs: List[str]):
    icons = ["🔴", "🟠", "🟡", "🟢", "🔵", "🟣"]
    for i, rec in enumerate(recs):
        icon = icons[i % len(icons)]
        st.markdown(
            f"""
            <div style="background:#0F172A;border:1px solid #1E40AF44;
                 border-radius:8px;padding:10px 14px;margin-bottom:6px;
                 display:flex;align-items:flex-start;gap:10px">
              <span style="font-size:1rem">{icon}</span>
              <span style="color:#CBD5E1;font-size:0.9rem">{rec}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
