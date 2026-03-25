"""
app.py
------
HIPAA Security Risk Assessment Framework — Streamlit Application

A professional, interactive SRA tool aligned to 45 CFR §§ 164.308–164.312.
Supports full assessment workflow: org setup → control scoring → gap analysis
→ remediation planning → PDF export.

Run: streamlit run app.py
"""

import json
import sys
import logging
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from src.controls import (
    CONTROLS, CONTROLS_BY_ID, CONTROLS_BY_SAFEGUARD,
    Safeguard, MATURITY_LABELS, get_summary,
)
from src.sra_engine import (
    SRASession, SRAEngine, ControlAssessment,
    create_new_assessment, ORG_SIZE_PROFILES,
    MATURITY_LABELS, LIKELIHOOD_LABELS, IMPACT_LABELS,
    RISK_TIER_THRESHOLDS,
)
from src.visualizations import (
    plot_compliance_gauge,
    plot_risk_heatmap,
    plot_domain_radar,
    plot_safeguard_bars,
    plot_tier_breakdown,
    plot_remediation_waterfall,
    plot_maturity_distribution,
)

logging.basicConfig(level=logging.WARNING)

# ─────────────────────────────────────────────────────────────
#  Page configuration
# ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="HIPAA SRA Framework",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main { font-family: 'Inter', system-ui, sans-serif; }
    .sra-card {
        background: white;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 16px 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        margin-bottom: 8px;
    }
    .control-header {
        font-size: 14px; font-weight: 700; color: #1E293B; margin-bottom: 4px;
    }
    .control-cfr {
        font-size: 11px; font-weight: 600; color: #0EA5E9;
        text-transform: uppercase; letter-spacing: 0.04em;
    }
    .badge-req { background:#FEE2E2; color:#991B1B; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; }
    .badge-addr { background:#DBEAFE; color:#1E40AF; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; }
    .badge-critical { background:#FEE2E2; color:#991B1B; padding:3px 10px; border-radius:10px; font-size:12px; font-weight:700; }
    .badge-high    { background:#FFEDD5; color:#9A3412; padding:3px 10px; border-radius:10px; font-size:12px; font-weight:700; }
    .badge-moderate{ background:#FEF3C7; color:#92400E; padding:3px 10px; border-radius:10px; font-size:12px; font-weight:700; }
    .badge-low     { background:#DCFCE7; color:#15803D; padding:3px 10px; border-radius:10px; font-size:12px; font-weight:700; }
    .risk-action { font-size:12px; color:#64748B; font-style:italic; margin-top:2px; }
    #MainMenu { visibility: hidden; } footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  Session state initialization
# ─────────────────────────────────────────────────────────────

def init_session():
    if "sra_session" not in st.session_state:
        st.session_state.sra_session = None
    if "current_page" not in st.session_state:
        st.session_state.current_page = "🏠 Setup"


init_session()


# ─────────────────────────────────────────────────────────────
#  Sidebar
# ─────────────────────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        st.markdown("## 🔐 HIPAA SRA")
        st.caption("Security Risk Assessment Framework")
        st.divider()

        pages = [
            "🏠 Setup",
            "📋 Assessment",
            "📊 Risk Dashboard",
            "🔍 Gap Analysis",
            "🗺️ Remediation Plan",
            "📄 Risk Register",
            "📖 HIPAA Reference",
        ]

        page = st.radio("Navigation", options=pages, label_visibility="collapsed")

        st.divider()

        if st.session_state.sra_session:
            sess = st.session_state.sra_session
            st.markdown(f"**Organization:** {sess.org_name or 'Unnamed'}")
            st.markdown(f"**Assessment Date:** {sess.assessment_date}")
            engine = SRAEngine(sess)
            summary = engine.compute_summary()
            score = summary.get("compliance_score", 0)
            color = "🟢" if score >= 70 else "🟡" if score >= 50 else "🔴"
            st.markdown(f"**Posture Score:** {color} {score:.0f}/100")
            st.markdown(f"**Progress:** {summary.get('completion_rate', 0):.0f}% documented")

        st.divider()

        # Save/load
        if st.session_state.sra_session:
            if st.button("💾 Export Session (JSON)", use_container_width=True):
                sess_json = json.dumps({
                    "org_name": st.session_state.sra_session.org_name,
                    "org_type": st.session_state.sra_session.org_type,
                    "assessor_name": st.session_state.sra_session.assessor_name,
                    "assessment_date": st.session_state.sra_session.assessment_date,
                    "assessments": {
                        cid: a.to_dict()
                        for cid, a in st.session_state.sra_session.assessments.items()
                    },
                }, indent=2)
                st.download_button(
                    "⬇️ Download JSON",
                    data=sess_json,
                    file_name=f"sra_{st.session_state.sra_session.org_name.replace(' ', '_')}.json",
                    mime="application/json",
                    use_container_width=True,
                )

        st.caption(f"Controls: {get_summary()['total_controls']} | "
                   f"Required: {get_summary()['required']} | "
                   f"Addressable: {get_summary()['addressable']}")

    return page


# ─────────────────────────────────────────────────────────────
#  Page: Setup
# ─────────────────────────────────────────────────────────────

def page_setup():
    st.markdown("# 🏠 Assessment Setup")
    st.markdown(
        "Configure your organization profile to initialize the HIPAA Security Risk Assessment. "
        "Profile selection pre-populates likelihood and impact scores appropriate to your "
        "organization type, which you can then refine control-by-control in the Assessment tab."
    )

    col1, col2 = st.columns([1.2, 1])

    with col1:
        st.markdown("#### Organization Information")
        org_name = st.text_input("Organization Name", placeholder="e.g., Valley Regional Medical Center")
        assessor_name = st.text_input("Assessor Name", placeholder="Your name")
        assessment_date = st.date_input("Assessment Date")
        scope = st.text_area(
            "Scope Description",
            placeholder="Describe which systems, locations, and ePHI types are in scope for this assessment...",
            height=100,
        )

        st.markdown("#### Organization Profile")
        org_type = st.selectbox(
            "Select the profile that best matches your organization:",
            options=list(ORG_SIZE_PROFILES.keys()),
            format_func=lambda k: ORG_SIZE_PROFILES[k]["label"],
        )

        profile = ORG_SIZE_PROFILES[org_type]
        st.markdown(f"""
        <div style="background:#EFF6FF; border:1px solid #BFDBFE; border-radius:8px; padding:12px; font-size:13px;">
            <strong>Profile Defaults:</strong><br>
            • Likelihood baseline: <strong>{profile['default_likelihood']}/5</strong>
            ({LIKELIHOOD_LABELS[profile['default_likelihood']]})<br>
            • Impact baseline: <strong>{profile['default_impact']}/5</strong>
            ({IMPACT_LABELS[profile['default_impact']]})<br>
            • Control maturity baseline: <strong>{profile['default_maturity']}/5</strong>
            ({MATURITY_LABELS[profile['default_maturity']]})
        </div>
        """, unsafe_allow_html=True)

        st.markdown("")
        if st.button("🚀 Initialize Assessment", type="primary", use_container_width=True):
            if not org_name.strip():
                st.error("Please enter an organization name.")
            else:
                session = create_new_assessment(
                    org_name=org_name.strip(),
                    org_type=org_type,
                    assessor_name=assessor_name.strip(),
                )
                session.assessment_date = str(assessment_date)
                session.scope_description = scope.strip()
                st.session_state.sra_session = session
                st.success(
                    f"✅ Assessment initialized for **{org_name}** with "
                    f"**{len(CONTROLS)}** HIPAA controls. Navigate to **Assessment** to begin scoring."
                )

    with col2:
        st.markdown("#### SRA Workflow Overview")
        st.markdown("""
        **Step 1: Setup** ← You are here
        Configure your organization profile and scope.

        **Step 2: Assessment**
        For each of the 74 HIPAA controls, rate:
        - Current maturity (0–5)
        - Likelihood of threat exploiting gap (1–5)
        - Impact if breach occurs (1–5)
        - Notes and evidence

        **Step 3: Risk Dashboard**
        Review your overall risk posture, compliance score, and risk heat map.

        **Step 4: Gap Analysis**
        Identify controls below acceptable maturity with regulatory context.

        **Step 5: Remediation Plan**
        Get a prioritized, milestone-based action plan.

        **Step 6: Risk Register**
        Export the complete risk register for documentation.
        """)

        st.markdown("#### Regulatory Basis")
        st.markdown("""
        This assessment covers all implementation specifications in:
        - **45 CFR § 164.308** — Administrative Safeguards (23 controls)
        - **45 CFR § 164.310** — Physical Safeguards (9 controls)
        - **45 CFR § 164.312** — Technical Safeguards (9 controls)

        Cross-referenced to:
        - NIST SP 800-66r2 (2023)
        - NIST Cybersecurity Framework 2.0
        - CIS Controls v8
        - HHS OCR Phase 2 Audit Protocol
        """)


# ─────────────────────────────────────────────────────────────
#  Page: Assessment
# ─────────────────────────────────────────────────────────────

def page_assessment():
    if not st.session_state.sra_session:
        st.warning("⚠️ Please complete Setup first.")
        return

    sess = st.session_state.sra_session

    st.markdown("# 📋 Control Assessment")
    st.markdown(
        "Rate each control's current implementation maturity, the likelihood a threat "
        "could exploit any gap, and the potential impact to patient data."
    )

    # Filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        safeguard_filter = st.selectbox(
            "Safeguard Category",
            options=["All", "Administrative", "Physical", "Technical"],
        )
    with col2:
        tier_filter = st.selectbox(
            "Show Controls by Risk Tier",
            options=["All", "Critical", "High", "Moderate", "Low"],
        )
    with col3:
        search = st.text_input("Search controls", placeholder="e.g., encryption, MFA, backup")

    filtered_controls = CONTROLS
    if safeguard_filter != "All":
        filtered_controls = [c for c in filtered_controls if c.safeguard.value == safeguard_filter]
    if search:
        filtered_controls = [
            c for c in filtered_controls
            if search.lower() in c.specification.lower()
            or search.lower() in c.standard.lower()
            or search.lower() in c.description.lower()
        ]
    if tier_filter != "All":
        filtered_controls = [
            c for c in filtered_controls
            if sess.assessments.get(c.id)
            and sess.assessments[c.id].risk_tier[0] == tier_filter
        ]

    st.caption(f"Showing {len(filtered_controls)} of {len(CONTROLS)} controls")

    # Group by safeguard
    safeguards_in_view = sorted(set(c.safeguard for c in filtered_controls), key=lambda s: s.value)
    for safeguard in safeguards_in_view:
        safeguard_controls = [c for c in filtered_controls if c.safeguard == safeguard]
        with st.expander(
            f"**{safeguard.value} Safeguards** — {len(safeguard_controls)} controls",
            expanded=(safeguard == Safeguard.ADMINISTRATIVE),
        ):
            for control in safeguard_controls:
                assessment = sess.assessments.get(control.id, ControlAssessment(control_id=control.id))
                tier_name, tier_color, tier_action = assessment.risk_tier

                desig_badge = (
                    '<span class="badge-req">Required</span>'
                    if control.designation.value == "Required"
                    else '<span class="badge-addr">Addressable</span>'
                )

                # Tier badge
                tier_class = tier_name.lower()
                tier_badge = f'<span class="badge-{tier_class}">{tier_name} Risk</span>'

                st.markdown(f"""
                <div class="sra-card">
                    <div class="control-cfr">{control.id} · {control.specification_cfr} · {desig_badge} · {tier_badge}</div>
                    <div class="control-header">{control.standard} → {control.specification}</div>
                    <div style="font-size:12px; color:#475569; margin-top:4px;">{control.description[:180]}...</div>
                </div>
                """, unsafe_allow_html=True)

                c1, c2, c3 = st.columns([1.5, 1, 1])

                with c1:
                    new_maturity = st.select_slider(
                        f"Maturity [{control.id}]",
                        options=list(MATURITY_LABELS.keys()),
                        value=assessment.maturity_score,
                        format_func=lambda x: f"{x} – {MATURITY_LABELS[x][:20]}",
                        label_visibility="collapsed",
                    )
                with c2:
                    new_likelihood = st.select_slider(
                        f"Likelihood [{control.id}]",
                        options=[1, 2, 3, 4, 5],
                        value=assessment.likelihood,
                        format_func=lambda x: f"L:{x} {LIKELIHOOD_LABELS[x]}",
                        label_visibility="collapsed",
                    )
                with c3:
                    new_impact = st.select_slider(
                        f"Impact [{control.id}]",
                        options=[1, 2, 3, 4, 5],
                        value=assessment.impact,
                        format_func=lambda x: f"I:{x} {IMPACT_LABELS[x]}",
                        label_visibility="collapsed",
                    )

                # Update session state in real time
                sess.assessments[control.id] = ControlAssessment(
                    control_id=control.id,
                    maturity_score=new_maturity,
                    likelihood=new_likelihood,
                    impact=new_impact,
                    notes=assessment.notes,
                    evidence_provided=assessment.evidence_provided,
                    not_applicable=assessment.not_applicable,
                )

                new_assessment = sess.assessments[control.id]
                st.caption(
                    f"Inherent Risk: **{new_assessment.inherent_risk:.0f}** | "
                    f"Effectiveness: **{new_assessment.control_effectiveness * 100:.0f}%** | "
                    f"Residual Risk: **{new_assessment.residual_risk:.1f}** | "
                    f"CFR: {control.standard_cfr}"
                )
                st.markdown("---")


# ─────────────────────────────────────────────────────────────
#  Page: Risk Dashboard
# ─────────────────────────────────────────────────────────────

def page_dashboard():
    if not st.session_state.sra_session:
        st.warning("⚠️ Please complete Setup first.")
        return

    engine = SRAEngine(st.session_state.sra_session)
    summary = engine.compute_summary()

    st.markdown(f"# 📊 Risk Dashboard — {summary['org_name']}")
    st.markdown(f"Assessment Date: **{summary['assessment_date']}** | "
                f"Assessor: **{summary['assessor_name']}**")

    # KPI row
    cols = st.columns(4)
    kpis = [
        ("Security Posture Score", f"{summary['compliance_score']:.0f}/100", "Higher is better"),
        ("Critical Findings", str(summary.get("critical_count", 0)), "Require immediate action"),
        ("High-Risk Findings", str(summary.get("high_count", 0)), "Address within 90 days"),
        ("Controls Assessed", f"{summary['total_controls']}", f"Documentation: {summary['completion_rate']:.0f}%"),
    ]
    for col, (label, value, sub) in zip(cols, kpis):
        col.markdown(f"""
        <div class="sra-card">
            <div style="font-size:11px; font-weight:600; color:#64748B; text-transform:uppercase;">{label}</div>
            <div style="font-size:28px; font-weight:800; color:#1E293B;">{value}</div>
            <div style="font-size:11px; color:#94A3B8;">{sub}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")

    # Alert for critical findings
    critical = summary.get("critical_count", 0)
    if critical > 0:
        st.markdown(
            f'<div style="background:#FEF2F2; border-left:4px solid #EF4444; padding:12px 16px; '
            f'border-radius:6px; font-size:13px; color:#991B1B; margin-bottom:12px;">'
            f'🚨 <strong>{critical} Critical finding(s) detected.</strong> '
            f'These require immediate executive notification and remediation. '
            f'Controls affected: {", ".join(summary.get("critical_findings", []))}</div>',
            unsafe_allow_html=True,
        )

    c1, c2 = st.columns([1, 1.5])
    with c1:
        st.plotly_chart(plot_compliance_gauge(summary["compliance_score"]), use_container_width=True)
        if summary.get("tier_counts"):
            st.plotly_chart(plot_tier_breakdown(summary["tier_counts"]), use_container_width=True)
    with c2:
        if summary.get("domain_scores"):
            st.plotly_chart(plot_domain_radar(summary["domain_scores"]), use_container_width=True)

    if summary.get("safeguard_scores"):
        st.plotly_chart(plot_safeguard_bars(summary["safeguard_scores"]), use_container_width=True)

    register = engine.build_risk_register()
    if register:
        st.plotly_chart(plot_maturity_distribution(register), use_container_width=True)

        st.plotly_chart(
            plot_risk_heatmap(register),
            use_container_width=True,
        )


# ─────────────────────────────────────────────────────────────
#  Page: Gap Analysis
# ─────────────────────────────────────────────────────────────

def page_gap_analysis():
    if not st.session_state.sra_session:
        st.warning("⚠️ Please complete Setup first.")
        return

    engine = SRAEngine(st.session_state.sra_session)
    gaps = engine.identify_gaps(min_maturity=3)

    st.markdown("# 🔍 Gap Analysis")
    st.markdown(
        f"**{len(gaps)} controls** fall below the target maturity of **3 (Defined/Documented)**. "
        "Controls are sorted by residual risk — highest first."
    )

    if not gaps:
        st.success("✅ No gaps identified at the Defined maturity level. Excellent posture!")
        return

    # Summary table
    for gap in gaps:
        tier = gap["risk_tier"]
        tier_class = tier.lower()
        desig = gap["designation"]
        desig_badge = '<span class="badge-req">Required</span>' if desig == "Required" else '<span class="badge-addr">Addressable</span>'
        tier_badge = f'<span class="badge-{tier_class}">{tier} Risk</span>'

        with st.expander(
            f"{gap['control_id']} · {gap['specification']} · Residual: {gap['residual_risk']:.1f}",
            expanded=(tier in ("Critical", "High")),
        ):
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(f"""
                {desig_badge} {tier_badge}

                **CFR:** {gap['cfr_citation']}  
                **Standard:** {gap['standard']}  
                **Domain:** {gap['risk_domain']}  
                **Current Maturity:** {gap['current_maturity']} — {gap['maturity_label']}  
                **Maturity Gap:** Needs {gap['gap']} level(s) of improvement to reach Defined  

                **Remediation Guidance:**
                > {gap['remediation_guidance']}
                """)
            with col2:
                st.markdown(f"""
                **Risk Scoring**
                - Inherent Risk: {gap['inherent_risk']:.0f}/25
                - Residual Risk: {gap['residual_risk']:.1f}/25
                - Likelihood: {gap['likelihood']}/5
                - Impact: {gap['impact']}/5

                **Required Action:**
                *{gap['risk_tier_action']}*

                **NIST CSF:**
                {", ".join(gap['nist_functions'])}

                **CIS Controls:**
                {", ".join(gap['cis_controls']) or "N/A"}
                """)


# ─────────────────────────────────────────────────────────────
#  Page: Remediation Plan
# ─────────────────────────────────────────────────────────────

def page_remediation():
    if not st.session_state.sra_session:
        st.warning("⚠️ Please complete Setup first.")
        return

    engine = SRAEngine(st.session_state.sra_session)
    plan = engine.generate_remediation_plan()

    st.markdown("# 🗺️ Remediation Action Plan")
    st.markdown(
        "Prioritized by: Risk Tier → Required vs. Addressable → Implementation Complexity. "
        "Quick wins (low complexity, high risk reduction) appear at the top."
    )

    if not plan:
        st.success("✅ All controls meet target maturity — no remediation actions required!")
        return

    if plan:
        st.plotly_chart(plot_remediation_waterfall(plan), use_container_width=True)

    milestones = [
        ("Immediate (0–30 days)", "🚨"),
        ("Short-Term (30–90 days)", "⚠️"),
        ("Medium-Term (90–180 days)", "📋"),
        ("Annual Plan (180–365 days)", "📅"),
    ]

    for milestone, icon in milestones:
        items = [p for p in plan if p.get("milestone") == milestone]
        if not items:
            continue
        st.markdown(f"### {icon} {milestone} — {len(items)} action(s)")
        for item in items:
            complexity_color = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}.get(item.get("complexity", "Medium"), "⚪")
            st.markdown(f"""
            **#{item['priority_rank']} {item['control_id']}** · {item['specification']}
            `{item['cfr_citation']}` · Complexity: {complexity_color} {item.get('complexity', 'Medium')}
            · Residual Risk: **{item['residual_risk']:.1f}**

            > {item['remediation_guidance'][:280]}...

            ---
            """)

    # Export remediation plan as CSV
    plan_df = pd.DataFrame([{
        "Priority": p["priority_rank"],
        "Milestone": p["milestone"],
        "Control ID": p["control_id"],
        "Specification": p["specification"],
        "CFR Citation": p["cfr_citation"],
        "Designation": p["designation"],
        "Risk Tier": p["risk_tier"],
        "Residual Risk": p["residual_risk"],
        "Complexity": p.get("complexity", "Medium"),
        "Remediation Guidance": p["remediation_guidance"],
    } for p in plan])

    csv = plan_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download Remediation Plan (CSV)",
        data=csv,
        file_name="hipaa_remediation_plan.csv",
        mime="text/csv",
        use_container_width=False,
    )


# ─────────────────────────────────────────────────────────────
#  Page: Risk Register
# ─────────────────────────────────────────────────────────────

def page_risk_register():
    if not st.session_state.sra_session:
        st.warning("⚠️ Please complete Setup first.")
        return

    engine = SRAEngine(st.session_state.sra_session)
    register = engine.build_risk_register()

    st.markdown("# 📄 Full Risk Register")
    st.markdown(
        "Complete control-by-control assessment results. "
        "Export to Excel for official SRA documentation or OCR submission support."
    )

    df = pd.DataFrame(register)

    # Tier filter
    tier_filter = st.multiselect(
        "Filter by Risk Tier",
        options=["Critical", "High", "Moderate", "Low"],
        default=["Critical", "High", "Moderate", "Low"],
    )
    if tier_filter:
        df = df[df["Risk Tier"].isin(tier_filter)]

    st.dataframe(
        df.style.apply(
            lambda col: col.map({
                "Critical": "background-color: #FEE2E2",
                "High": "background-color: #FFEDD5",
                "Moderate": "background-color: #FEF3C7",
                "Low": "background-color: #DCFCE7",
            }) if col.name == "Risk Tier" else [""] * len(col),
            axis=0,
        ),
        use_container_width=True,
        height=520,
    )

    col1, col2 = st.columns(2)
    with col1:
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Risk Register (CSV)",
            data=csv,
            file_name="hipaa_risk_register.csv",
            mime="text/csv",
            use_container_width=True,
        )


# ─────────────────────────────────────────────────────────────
#  Page: HIPAA Reference
# ─────────────────────────────────────────────────────────────

def page_reference():
    st.markdown("# 📖 HIPAA Security Rule Quick Reference")

    st.markdown("""
    ## 45 CFR § 164.306 — General Requirements

    Covered entities and business associates must:
    1. **Ensure** the confidentiality, integrity, and availability of all ePHI they create, receive, maintain, or transmit
    2. **Protect** against any reasonably anticipated threats or hazards to the security or integrity of ePHI
    3. **Protect** against any reasonably anticipated uses or disclosures not permitted by the Privacy Rule
    4. **Ensure** compliance by their workforce

    ---

    ## Safeguard Summary

    | Safeguard | CFR Section | Controls in This Tool |
    |---|---|---|
    | Administrative | § 164.308 | 23 controls |
    | Physical | § 164.310 | 9 controls |
    | Technical | § 164.312 | 9 controls |

    ---

    ## Required vs. Addressable

    **Required specifications** must be implemented as stated — no exceptions.

    **Addressable specifications** must either be:
    - Implemented as specified, **OR**
    - Documented with an alternative equivalent measure, **OR**
    - Documented with a rationale for why it is not reasonable and appropriate

    ⚠️ *Addressable does NOT mean optional.*

    ---

    ## HIPAA Breach: The "Safe Harbor" Rule

    A breach does NOT require OCR notification if:
    - The data was **encrypted** at the time of the incident using NIST-approved methods (AES-256), AND
    - The decryption key was not compromised

    This makes encryption one of the **highest-ROI** security controls in HIPAA compliance.

    ---

    ## Key HHS OCR Enforcement Trends (2022–2024)

    | Issue | Settlement Range |
    |---|---|
    | Lack of Security Risk Analysis | $200K–$1.9M |
    | Insufficient Access Controls | $250K–$3.5M |
    | Failure to Encrypt ePHI | $100K–$5.1M |
    | No Business Associate Agreement | $500K–$2.3M |
    | Ransomware (inadequate risk management) | $250K–$4.75M |

    ---

    ## Key Resources

    - [HHS OCR HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
    - [NIST SP 800-66r2](https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final)
    - [HHS SRA Tool](https://www.healthit.gov/topic/privacy-security-and-hipaa/security-risk-assessment-tool)
    - [HHS OCR Enforcement Actions](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html)
    - [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
    """)


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    page = render_sidebar()

    if "Setup" in page:
        page_setup()
    elif "Assessment" in page:
        page_assessment()
    elif "Dashboard" in page:
        page_dashboard()
    elif "Gap" in page:
        page_gap_analysis()
    elif "Remediation" in page:
        page_remediation()
    elif "Register" in page:
        page_risk_register()
    elif "Reference" in page:
        page_reference()


if __name__ == "__main__":
    main()
