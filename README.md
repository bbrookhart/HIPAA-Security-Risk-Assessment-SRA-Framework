# 🔐 HIPAA Security Risk Assessment Framework

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![HIPAA](https://img.shields.io/badge/HIPAA-Security%20Rule%20Compliant-0EA5E9?style=for-the-badge)
![NIST](https://img.shields.io/badge/NIST%20CSF-2.0%20Aligned-6366F1?style=for-the-badge)
![License: MIT](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-22C55E?style=for-the-badge)
![HHS OCR](https://img.shields.io/badge/HHS%20OCR-Audit%20Protocol%20Aligned-F59E0B?style=for-the-badge)

**A production-grade HIPAA Security Risk Assessment engine aligned to 45 CFR § 164,
the HHS OCR Audit Protocol, and NIST Cybersecurity Framework 2.0.**

*Transforms the federally mandated SRA from a compliance checkbox into an operational
security intelligence process.*

[🚀 Live Demo](#deployment) · [📋 Controls Database](#hipaa-controls-coverage) · [📄 White Paper](whitepaper/HIPAA_SRA_Whitepaper.md) · [🧪 Methodology](#scoring-methodology)

</div>

---

## 📌 The Problem

HIPAA's Security Rule (45 CFR § 164.306) requires every covered entity and business associate to conduct an accurate and thorough **Security Risk Assessment (SRA)**. Yet:

- **83%** of healthcare organizations that received HHS OCR audit findings had deficiencies in their SRA process *(HHS OCR Phase 2 Audit Report, 2020)*
- The average cost of a HIPAA violation settlement is **$1.2 million** — most of which stems from demonstrably inadequate risk management
- The HHS SRA Tool (the government's own offering) is a static Excel spreadsheet with no scoring model, no remediation prioritization, and no executive reporting

This framework replaces that approach with a **structured, scored, and reportable SRA process** grounded in all three HIPAA safeguard categories, cross-referenced to NIST CSF 2.0 and CIS Controls v8.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📋 **Complete Controls Library** | 74 controls across Administrative, Physical, and Technical safeguards, mapped to exact CFR citations |
| 🎯 **Risk Scoring Engine** | Likelihood × Impact matrix with residual risk calculation after control credit |
| 🏥 **Organization Profiles** | Size-tiered profiles (small practice to large health system) with pre-seeded baselines |
| 📊 **Risk Heat Map** | Visual likelihood/impact matrix across all HIPAA domains |
| 🔴 **Prioritized Remediation** | Ranked action plan sorted by risk reduction potential and implementation complexity |
| 📄 **PDF Report Generator** | Executive summary + technical annex formatted for board presentation or OCR submission |
| 🔗 **NIST CSF 2.0 Crosswalk** | Every control mapped to NIST CSF functions (Govern, Identify, Protect, Detect, Respond, Recover) |
| 🔗 **CIS Controls v8 Crosswalk** | Secondary mapping to CIS Controls for implementation guidance |
| 💾 **Session Persistence** | Save/load assessment state as JSON for multi-session assessments |

---

## 🏗️ HIPAA Controls Coverage

The framework covers all **Required** and **Addressable** implementation specifications across the three HIPAA safeguard domains:

### Administrative Safeguards (§164.308) — 28 Controls
| Standard | Specifications | Required/Addressable |
|---|---|---|
| Security Management Process | Risk Analysis, Risk Management, Sanction Policy, Information System Activity Review | Required |
| Assigned Security Responsibility | Security Official designation | Required |
| Workforce Security | Authorization, Clearance, Termination Procedures | Addressable |
| Information Access Management | Isolating Healthcare Clearinghouse, Access Authorization, Access Establishment | Required/Addressable |
| Security Awareness & Training | Security Reminders, Protection from Malware, Log-in Monitoring, Password Management | Addressable |
| Security Incident Procedures | Response and Reporting | Required |
| Contingency Plan | Data Backup, Disaster Recovery, Emergency Mode Operation, Testing, Applications Criticality | Required/Addressable |
| Evaluation | Periodic Technical and Non-Technical Evaluation | Required |
| Business Associate Contracts | Written contracts/arrangements | Required |

### Physical Safeguards (§164.310) — 18 Controls
| Standard | Specifications | Required/Addressable |
|---|---|---|
| Facility Access Controls | Contingency Operations, Facility Security Plan, Access Control, Maintenance Records | Addressable |
| Workstation Use | Workstation use policies | Required |
| Workstation Security | Physical safeguards for workstations | Required |
| Device and Media Controls | Disposal, Media Re-Use, Accountability, Data Backup | Required/Addressable |

### Technical Safeguards (§164.312) — 28 Controls
| Standard | Specifications | Required/Addressable |
|---|---|---|
| Access Control | Unique User Identification, Emergency Access, Automatic Logoff, Encryption/Decryption | Required/Addressable |
| Audit Controls | Hardware, software, procedural mechanisms | Required |
| Integrity | Mechanism to authenticate ePHI | Addressable |
| Person/Entity Authentication | Verify identity | Required |
| Transmission Security | Integrity Controls, Encryption | Addressable |

---

## 🧪 Scoring Methodology

### Risk Calculation Model

```
Inherent Risk Score = Likelihood (1–5) × Impact (1–5)
                    = 1 (minimal) to 25 (critical)

Control Effectiveness Score = Σ(control_maturity × control_weight) / Σ(control_weight)
                            = 0.0 (no controls) to 1.0 (fully mature)

Residual Risk Score = Inherent Risk × (1 - Control Effectiveness)
```

### Likelihood Scale
| Score | Level | Criteria |
|---|---|---|
| 1 | Very Low | Threat source lacks capability or motivation; controls highly effective |
| 2 | Low | Threat source has limited capability; strong mitigating controls |
| 3 | Medium | Threat source has capability; controls partially effective |
| 4 | High | Threat source highly motivated and capable; controls incomplete |
| 5 | Very High | Threat source extremely motivated; controls absent or failed |

### Impact Scale
| Score | Level | PHI Impact | Operational Impact |
|---|---|---|---|
| 1 | Very Low | <10 records; no financial/reputational harm | Minimal disruption |
| 2 | Low | 10–499 records; limited harm | Short-term disruption |
| 3 | Medium | 500–9,999 records; moderate harm | Multi-day disruption |
| 4 | High | 10K–499K records; significant harm | Extended outage |
| 5 | Very High | 500K+ records; catastrophic harm | Mission-critical failure |

### Control Maturity Scale (Per Control)
| Score | Level | Description |
|---|---|---|
| 0 | Not Implemented | Control does not exist |
| 1 | Initial | Ad hoc; undocumented; relies on individual effort |
| 2 | Developing | Partially documented; inconsistently applied |
| 3 | Defined | Documented; consistently applied; not yet measured |
| 4 | Managed | Documented; measured; actively monitored |
| 5 | Optimizing | Continuously improving; benchmarked; automated where possible |

### Risk Tier Thresholds
| Residual Score | Tier | Action Required |
|---|---|---|
| 0–5 | 🟢 Low | Monitor; re-assess annually |
| 6–10 | 🟡 Moderate | Address within 12 months; include in security plan |
| 11–16 | 🟠 High | Address within 90 days; escalate to leadership |
| 17–25 | 🔴 Critical | Immediate action; executive notification required |

---

## 📁 Project Structure

```
hipaa-sra-framework/
│
├── README.md
├── app.py                          ← Streamlit SRA application
├── requirements.txt
├── .gitignore
│
├── src/
│   ├── __init__.py
│   ├── controls.py                 ← Complete HIPAA controls database (74 controls)
│   ├── sra_engine.py               ← Risk scoring, gap analysis, remediation engine
│   ├── report_generator.py         ← PDF executive summary + technical annex
│   └── visualizations.py           ← Risk heat maps and scoring charts
│
├── whitepaper/
│   └── HIPAA_SRA_Whitepaper.md     ← Publication-ready academic/practitioner paper
│
└── tests/
    ├── test_controls.py
    └── test_sra_engine.py
```

---

## 🚀 Installation

```bash
git clone https://github.com/YOUR_USERNAME/hipaa-sra-framework.git
cd hipaa-sra-framework

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

streamlit run app.py
```

---

## 📊 Output: What the SRA Produces

### Executive Summary Report
- Overall organizational risk posture (scored 0–100)
- Critical and High risk findings requiring immediate attention
- Remediation roadmap with effort/impact prioritization matrix
- Trend comparison if prior assessment data exists

### Technical Annex
- Full control-by-control assessment results
- Likelihood × Impact justification narratives
- NIST CSF and CIS Controls crosswalk table
- Supporting evidence checklist

### Remediation Action Plan
- Prioritized list of remediation tasks
- Estimated implementation complexity (Low/Medium/High)
- Regulatory citation for each finding
- 30/60/90-day milestone template

---

## 📖 White Paper

The companion white paper [`whitepaper/HIPAA_SRA_Whitepaper.md`](whitepaper/HIPAA_SRA_Whitepaper.md) provides:

- Academic framing of the SRA problem in post-HITECH healthcare
- Comparative analysis of existing SRA methodologies
- Theoretical basis for the Likelihood × Impact model
- Case study: How inadequate SRA contributed to major breach settlements
- Policy recommendations for CMS and HHS OCR

*Suitable for submission to HIMSS, AMIA, or Journal of Healthcare Information Management.*

---

## 🔐 Legal & Compliance Disclaimer

This tool is designed to **support** — not replace — the judgment of qualified healthcare compliance professionals. Completion of this assessment does not guarantee HIPAA compliance or protection from HHS OCR enforcement action. Organizations should engage qualified legal counsel and certified compliance professionals when conducting official Security Risk Assessments.

**This tool does not collect, store, or transmit any Protected Health Information (PHI).**

---

## 👤 Author

**Brian Brookhart** | Cybersecurity & Health Informatics Professional

---

## 📄 Regulatory References

- 45 CFR § 164.306 — General Requirements (Security Rule)
- 45 CFR § 164.308 — Administrative Safeguards
- 45 CFR § 164.310 — Physical Safeguards
- 45 CFR § 164.312 — Technical Safeguards
- HHS OCR Phase 2 Audit Protocol (2016, updated 2023)
- NIST SP 800-66r2 — Implementing the HIPAA Security Rule (2023)
- NIST Cybersecurity Framework 2.0 (2024)
- CIS Controls v8 (2021)

---

<div align="center">

*Built to make healthcare security risk management rigorous, repeatable, and actionable.*

</div>
