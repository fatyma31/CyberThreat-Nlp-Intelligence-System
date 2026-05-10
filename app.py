"""
Main Streamlit Application — CyberGuard AI Threat Intelligence Platform
"""
 
import sys
import os
from pathlib import Path
 
# Ensure project root is on path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
 
import streamlit as st
from engine import ThreatIntelEngine
from report_generator import generate_pdf_report
from components import (
    render_metric_card, render_threat_badge, render_probability_chart,
    render_risk_gauge, render_confidence_donut, render_entity_tags,
    render_keyword_pills, render_reasoning, render_recommendations,
)
from settings import APP_TITLE, APP_ICON, THREAT_CLASSES
 
# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title=APP_TITLE,
    page_icon=APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)
 
# ─── Global CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
 
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0A0E1A;
    color: #E2E8F0;
}
.stApp { background: #0A0E1A; }
 
/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0D1B2A 0%, #111827 100%);
    border-right: 1px solid #1E293B;
}
 
/* Text areas / inputs */
textarea, .stTextArea textarea {
    background: #111827 !important;
    color: #E2E8F0 !important;
    border: 1px solid #1E40AF55 !important;
    border-radius: 10px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.9rem !important;
}
 
/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #1565C0, #0D47A1) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 700 !important;
    font-size: 1rem !important;
    padding: 12px 32px !important;
    letter-spacing: 0.05em !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 4px 20px #1565C044 !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #1976D2, #1565C0) !important;
    box-shadow: 0 6px 28px #1565C077 !important;
    transform: translateY(-1px) !important;
}
 
/* Download button */
.stDownloadButton > button {
    background: linear-gradient(135deg, #00695C, #004D40) !important;
    color: white !important; border: none !important;
    border-radius: 8px !important; font-weight: 600 !important;
}
 
/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: #111827 !important;
    border-radius: 10px !important;
    padding: 4px !important;
    border: 1px solid #1E293B !important;
}
.stTabs [data-baseweb="tab"] {
    color: #64748B !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
}
.stTabs [aria-selected="true"] {
    background: #1E40AF !important;
    color: white !important;
}
 
/* Expanders */
.streamlit-expanderHeader {
    background: #111827 !important;
    border: 1px solid #1E293B !important;
    border-radius: 8px !important;
    color: #CBD5E1 !important;
}
 
/* Divider */
hr { border-color: #1E293B !important; }
 
/* Hide Streamlit branding */
#MainMenu, footer, header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)
 
# ─── Session State Init ───────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []
if "report" not in st.session_state:
    st.session_state.report = None
 
# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:20px 0 10px">
      <div style="font-size:3rem">🛡️</div>
      <div style="font-size:1.1rem;font-weight:800;color:#00E5FF;letter-spacing:0.1em">
        CYBERGUARD AI
      </div>
      <div style="font-size:0.72rem;color:#475569;letter-spacing:0.15em;margin-top:4px">
        THREAT INTELLIGENCE PLATFORM
      </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()
 
    st.markdown("### 🎯 Quick Test Samples")
    samples = {
        "🎣 Phishing": "Urgent: Your PayPal account will be suspended unless you verify credentials at http://paypal-secure-alert.xyz/login immediately.",
        "🦠 Malware": "The trojan establishes persistence via registry run keys and communicates with C2 server over encrypted channels using reflective DLL injection.",
        "💰 Ransomware": "LockBit 3.0 encrypted all network shares. Demands 2 BTC within 72 hours or stolen data published publicly.",
        "💥 DDoS": "Botnet of 500k IoT devices launching 2.3 Tbps UDP flood attack causing complete service unavailability.",
        "💉 SQL Inject": "UNION SELECT username, password FROM users WHERE OR 1=1 -- exploiting blind SQL injection to dump the database.",
        "✅ Benign": "Monthly security audit completed. All firewall rules updated. No threats detected. Compliance verified.",
    }
    for label, text in samples.items():
        if st.button(label, use_container_width=True, key=f"sample_{label}"):
            st.session_state["sample_text"] = text
 
    st.divider()
    st.markdown("### ⚙️ Settings")
    show_raw = st.checkbox("Show cleaned text", value=False)
    show_history = st.checkbox("Show analysis history", value=True)
 
    st.divider()
    st.markdown("""
    <div style="color:#475569;font-size:0.72rem;text-align:center">
      Powered by DistilBERT + spaCy<br>v1.0.0 — CyberGuard AI
    </div>
    """, unsafe_allow_html=True)
 
# ─── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#0D47A1,#1565C0,#0D47A1);
     border-radius:16px;padding:24px 32px;margin-bottom:24px;
     border:1px solid #1E40AF55;">
  <h1 style="color:#00E5FF;font-size:2rem;font-weight:800;margin:0;letter-spacing:0.05em">
    🛡️ CyberGuard AI — Threat Intelligence Platform
  </h1>
  <p style="color:#93C5FD;margin:8px 0 0;font-size:1rem">
    Real-time NLP-powered cyber threat detection • DistilBERT classification •
    Explainable AI • Threat intelligence reports
  </p>
</div>
""", unsafe_allow_html=True)
 
# ─── Input Area ───────────────────────────────────────────────────────────────
col_input, col_info = st.columns([3, 1])
 
with col_input:
    default_text = st.session_state.get("sample_text", "")
    input_text = st.text_area(
        "📝 Enter threat text to analyze",
        value=default_text,
        height=160,
        placeholder="Paste email content, log entries, incident descriptions, threat reports, or any cybersecurity-related text here...",
        key="input_text_area",
    )
    analyze_btn = st.button("🔍 Analyze Threat", use_container_width=True, type="primary")
 
with col_info:
    st.markdown("""
    <div style="background:#111827;border:1px solid #1E293B;border-radius:12px;padding:16px;">
      <div style="color:#00E5FF;font-weight:700;margin-bottom:10px">🎯 Detects</div>
    """, unsafe_allow_html=True)
    for t in THREAT_CLASSES:
        icons = {"Benign": "✅", "Phishing": "🎣", "Malware": "🦠",
                 "Ransomware": "💰", "DDoS": "💥", "SQL Injection": "💉"}
        st.markdown(f"<div style='color:#CBD5E1;font-size:0.85rem;padding:2px 0'>"
                    f"{icons.get(t,'⚠️')} {t}</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
 
# ─── Analysis ─────────────────────────────────────────────────────────────────
if analyze_btn and input_text.strip():
    engine = ThreatIntelEngine()
 
    with st.spinner("🔍 Analyzing threat intelligence..."):
        report = engine.analyze(input_text)
 
    st.session_state.report = report
    st.session_state.history.append({
        "text":     input_text[:80] + "..." if len(input_text) > 80 else input_text,
        "threat":   report["threat"],
        "severity": report["severity_level"],
        "score":    report["risk_score"],
    })
 
elif analyze_btn and not input_text.strip():
    st.warning("⚠️ Please enter some text before analyzing.")
 
# ─── Results ──────────────────────────────────────────────────────────────────
report = st.session_state.report
 
if report:
    st.divider()
    st.markdown("## 📊 Analysis Results")
 
    # ── Top metrics row ────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_metric_card("Threat Type", report["threat"], "⚠️",
                           report["severity_color"])
    with c2:
        render_metric_card("Severity", report["severity_level"], "🔥",
                           report["severity_color"])
    with c3:
        render_metric_card("Confidence", f"{report['confidence']:.1f}%", "🎯",
                           "#00E5FF")
    with c4:
        render_metric_card("Risk Score", f"{report['risk_score']}/100", "📈",
                           "#FF6D00" if report["risk_score"] > 50 else "#00C853")
 
    st.markdown("")
 
    # ── Main tabs ──────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🎯 Classification", "🔍 Entities & Keywords",
        "🧠 Explainability", "📋 Recommendations", "📄 Report"
    ])
 
    # ── TAB 1: Classification ──────────────────────────────────────────────
    with tab1:
        col_a, col_b, col_c = st.columns([2, 2, 1.5])
 
        with col_a:
            st.markdown("#### 📊 Probability Distribution")
            fig_bar = render_probability_chart(report["probabilities"])
            st.plotly_chart(fig_bar, use_container_width=True)
 
        with col_b:
            st.markdown("#### 🎯 Risk Gauge")
            fig_gauge = render_risk_gauge(report["risk_score"])
            st.plotly_chart(fig_gauge, use_container_width=True)
 
        with col_c:
            st.markdown("#### 🏷️ Threat")
            render_threat_badge(report["threat"], report["severity_level"],
                                report["severity_color"])
            st.markdown("#### 🔵 Confidence")
            fig_donut = render_confidence_donut(
                report["confidence"], report["threat"], report["severity_color"]
            )
            st.plotly_chart(fig_donut, use_container_width=True)
 
        if show_raw:
            with st.expander("🔧 Cleaned / Preprocessed Text"):
                st.code(report.get("cleaned_text", ""), language="text")
 
    # ── TAB 2: Entities & Keywords ─────────────────────────────────────────
    with tab2:
        col_e, col_k = st.columns(2)
        with col_e:
            st.markdown("#### 🔎 Named Entities (NER)")
            render_entity_tags(report["entities"])
 
        with col_k:
            st.markdown("#### 🏷️ Cyber Threat Keywords")
            render_keyword_pills(report["top_keywords"])
 
            if report["keyword_map"]:
                st.markdown("#### 📂 Keywords by Category")
                for cat, kws in report["keyword_map"].items():
                    with st.expander(f"🗂 {cat.replace('_', ' ').title()} ({len(kws)})"):
                        st.write(", ".join(kws))
 
    # ── TAB 3: Explainability ──────────────────────────────────────────────
    with tab3:
        st.markdown("#### 🧠 AI Reasoning")
        render_reasoning(report["reasoning"], report["severity_color"])
 
        st.markdown("#### 📈 Classification Breakdown")
        prob_df_data = {
            "Threat Class": list(report["probabilities"].keys()),
            "Probability (%)": list(report["probabilities"].values()),
        }
        import pandas as pd
        st.dataframe(
            pd.DataFrame(prob_df_data).sort_values("Probability (%)", ascending=False),
            use_container_width=True, hide_index=True,
        )
 
    # ── TAB 4: Recommendations ────────────────────────────────────────────
    with tab4:
        st.markdown("#### ✅ Recommended Actions")
        render_recommendations(report["recommendations"])
 
    # ── TAB 5: Report ─────────────────────────────────────────────────────
    with tab5:
        st.markdown("#### 📄 Generate Threat Intelligence Report")
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            if st.button("📥 Generate PDF Report", use_container_width=True):
                with st.spinner("Generating report..."):
                    try:
                        path = generate_pdf_report(report)
                        with open(path, "rb") as f:
                            st.download_button(
                                "⬇️ Download PDF Report",
                                data=f.read(),
                                file_name=Path(path).name,
                                mime="application/pdf",
                                use_container_width=True,
                            )
                        st.success(f"✅ Report saved: {path}")
                    except Exception as e:
                        st.error(f"Error generating PDF: {e}")
 
        with col_r2:
            st.markdown("**📋 Report Summary**")
            st.json({
                "Threat": report["threat"],
                "Severity": report["severity_level"],
                "Confidence": f"{report['confidence']:.1f}%",
                "Risk Score": report["risk_score"],
                "Entities Found": {k: len(v) for k, v in report["entities"].items()},
                "Keywords Found": len(report["top_keywords"]),
                "Model": report.get("model_source", "N/A"),
            })
 
# ─── History Panel ────────────────────────────────────────────────────────────
if show_history and st.session_state.history:
    st.divider()
    st.markdown("### 🕒 Analysis History")
    import pandas as pd
    hist_df = pd.DataFrame(st.session_state.history[::-1])
    st.dataframe(hist_df, use_container_width=True, hide_index=True)
 
elif not report:
    st.markdown("""
    <div style="text-align:center;padding:60px 0;color:#475569;">
      <div style="font-size:4rem">🛡️</div>
      <div style="font-size:1.2rem;font-weight:600;margin-top:16px;color:#64748B">
        Enter text above and click Analyze to begin threat detection
      </div>
      <div style="font-size:0.9rem;margin-top:8px">
        Supports phishing, malware, ransomware, DDoS, SQL injection detection
      </div>
    </div>
    """, unsafe_allow_html=True)
 







