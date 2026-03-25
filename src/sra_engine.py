"""
src/sra_engine.py
-----------------
HIPAA Security Risk Assessment scoring engine.

Implements the Likelihood × Impact risk model with residual risk calculation,
control effectiveness scoring, gap analysis, and remediation prioritization.

The scoring model is based on:
  - NIST SP 800-30r1 Risk Assessment Methodology
  - HHS OCR HIPAA Security Rule Audit Protocol
  - NIST SP 800-66r2 Implementation Guidance

All calculations are deterministic and audit-traceable.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.controls import (
    CONTROLS,
    CONTROLS_BY_ID,
    CONTROLS_BY_SAFEGUARD,
    HIPAAControl,
    Safeguard,
    Designation,
    RiskDomain,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────

MATURITY_LABELS = {
    0: "Not Implemented",
    1: "Initial (Ad Hoc)",
    2: "Developing (Partial)",
    3: "Defined (Documented)",
    4: "Managed (Measured)",
    5: "Optimizing (Continuous Improvement)",
}

LIKELIHOOD_LABELS = {
    1: "Very Low",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Very High",
}

IMPACT_LABELS = {
    1: "Very Low",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Very High",
}

RISK_TIER_THRESHOLDS = [
    (0, 5, "Low", "#22C55E", "Monitor; re-assess annually"),
    (6, 10, "Moderate", "#F59E0B", "Address within 12 months"),
    (11, 16, "High", "#F97316", "Address within 90 days; escalate to leadership"),
    (17, 25, "Critical", "#EF4444", "Immediate action required; executive notification"),
]

ORG_SIZE_PROFILES = {
    "small_practice": {
        "label": "Small Practice (1–10 providers)",
        "default_likelihood": 3,
        "default_impact": 3,
        "default_maturity": 1,
    },
    "medium_group": {
        "label": "Medium Group Practice (11–100 providers)",
        "default_likelihood": 3,
        "default_impact": 4,
        "default_maturity": 2,
    },
    "community_hospital": {
        "label": "Community Hospital (100–500 beds)",
        "default_likelihood": 4,
        "default_impact": 4,
        "default_maturity": 2,
    },
    "large_health_system": {
        "label": "Large Health System (500+ beds / multi-site)",
        "default_likelihood": 4,
        "default_impact": 5,
        "default_maturity": 3,
    },
    "health_plan": {
        "label": "Health Plan / Payer",
        "default_likelihood": 4,
        "default_impact": 5,
        "default_maturity": 3,
    },
    "business_associate": {
        "label": "Business Associate / Vendor",
        "default_likelihood": 3,
        "default_impact": 4,
        "default_maturity": 2,
    },
}


# ─────────────────────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────────────────────

@dataclass
class ControlAssessment:
    """Assessment result for a single HIPAA control."""
    control_id: str
    maturity_score: int = 0          # 0–5: control implementation maturity
    likelihood: int = 3              # 1–5: probability of threat exploiting gap
    impact: int = 3                  # 1–5: impact if threat is realized
    notes: str = ""                  # Assessor narrative
    evidence_provided: list[str] = field(default_factory=list)
    not_applicable: bool = False     # e.g., clearinghouse isolation for non-clearinghouses

    @property
    def inherent_risk(self) -> float:
        """Raw risk before considering controls."""
        return float(self.likelihood * self.impact)

    @property
    def control_effectiveness(self) -> float:
        """Control effectiveness as a decimal (0.0–1.0) based on maturity."""
        # Maturity-to-effectiveness mapping (non-linear: first 2 levels provide
        # disproportionately low coverage)
        effectiveness_map = {0: 0.0, 1: 0.05, 2: 0.25, 3: 0.55, 4: 0.80, 5: 1.0}
        return effectiveness_map.get(self.maturity_score, 0.0)

    @property
    def residual_risk(self) -> float:
        """Risk remaining after applying current control effectiveness."""
        if self.not_applicable:
            return 0.0
        return self.inherent_risk * (1.0 - self.control_effectiveness)

    @property
    def risk_tier(self) -> tuple[str, str, str]:
        """(tier_name, color_hex, action_text) based on residual risk."""
        score = self.residual_risk
        for low, high, tier, color, action in RISK_TIER_THRESHOLDS:
            if low <= score <= high:
                return tier, color, action
        return "Unknown", "#94A3B8", "Review required"

    @property
    def risk_reduction_potential(self) -> float:
        """How much risk could be reduced by fully implementing this control."""
        return self.inherent_risk - (self.inherent_risk * (1.0 - 1.0))  # full effectiveness

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SRASession:
    """
    A complete Security Risk Assessment session for one organization.
    Serializable to/from JSON for save/load functionality.
    """
    # Organization info
    org_name: str = ""
    org_type: str = "community_hospital"
    assessor_name: str = ""
    assessment_date: str = field(default_factory=lambda: datetime.today().strftime("%Y-%m-%d"))
    assessment_period: str = ""
    previous_assessment_date: str = ""
    scope_description: str = ""

    # Control assessments — keyed by control ID
    assessments: dict[str, ControlAssessment] = field(default_factory=dict)

    # Metadata
    version: str = "1.0"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_modified: str = field(default_factory=lambda: datetime.now().isoformat())

    def initialize_defaults(self):
        """Pre-populate all controls with profile-appropriate defaults."""
        profile = ORG_SIZE_PROFILES.get(self.org_type, ORG_SIZE_PROFILES["community_hospital"])
        for control in CONTROLS:
            if control.id not in self.assessments:
                self.assessments[control.id] = ControlAssessment(
                    control_id=control.id,
                    maturity_score=profile["default_maturity"],
                    likelihood=profile["default_likelihood"],
                    impact=profile["default_impact"],
                )

    def save(self, filepath: str | Path):
        """Serialize session to JSON file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        self.last_modified = datetime.now().isoformat()
        data = {
            "org_name": self.org_name,
            "org_type": self.org_type,
            "assessor_name": self.assessor_name,
            "assessment_date": self.assessment_date,
            "assessment_period": self.assessment_period,
            "previous_assessment_date": self.previous_assessment_date,
            "scope_description": self.scope_description,
            "version": self.version,
            "created_at": self.created_at,
            "last_modified": self.last_modified,
            "assessments": {
                cid: a.to_dict() for cid, a in self.assessments.items()
            },
        }
        filepath.write_text(json.dumps(data, indent=2))
        logger.info(f"Session saved to {filepath}")

    @classmethod
    def load(cls, filepath: str | Path) -> "SRASession":
        """Load a session from a JSON file."""
        data = json.loads(Path(filepath).read_text())
        session = cls(
            org_name=data.get("org_name", ""),
            org_type=data.get("org_type", "community_hospital"),
            assessor_name=data.get("assessor_name", ""),
            assessment_date=data.get("assessment_date", ""),
            assessment_period=data.get("assessment_period", ""),
            previous_assessment_date=data.get("previous_assessment_date", ""),
            scope_description=data.get("scope_description", ""),
            version=data.get("version", "1.0"),
            created_at=data.get("created_at", ""),
            last_modified=data.get("last_modified", ""),
        )
        for cid, a_data in data.get("assessments", {}).items():
            session.assessments[cid] = ControlAssessment(
                control_id=a_data.get("control_id", cid),
                maturity_score=a_data.get("maturity_score", 0),
                likelihood=a_data.get("likelihood", 3),
                impact=a_data.get("impact", 3),
                notes=a_data.get("notes", ""),
                evidence_provided=a_data.get("evidence_provided", []),
                not_applicable=a_data.get("not_applicable", False),
            )
        return session


# ─────────────────────────────────────────────────────────────
#  Scoring engine
# ─────────────────────────────────────────────────────────────

class SRAEngine:
    """
    Core scoring and analysis engine for HIPAA Security Risk Assessments.

    Usage:
        engine = SRAEngine(session)
        summary = engine.compute_summary()
        gaps = engine.identify_gaps()
        plan = engine.generate_remediation_plan()
    """

    def __init__(self, session: SRASession):
        self.session = session

    # ── Aggregate scoring ─────────────────────────────────────

    def compute_summary(self) -> dict[str, Any]:
        """
        Compute aggregate risk summary across all controls.

        Returns
        -------
        dict with overall score, domain scores, tier breakdown, completion rate
        """
        if not self.session.assessments:
            return self._empty_summary()

        assessments = list(self.session.assessments.values())
        applicable = [a for a in assessments if not a.not_applicable]

        if not applicable:
            return self._empty_summary()

        total_inherent = sum(a.inherent_risk for a in applicable)
        total_residual = sum(a.residual_risk for a in applicable)
        max_possible = len(applicable) * 25.0  # 5 × 5 per control

        # Overall risk posture score: 0 (no risk) to 100 (maximum risk)
        overall_residual_pct = (total_residual / max_possible) * 100 if max_possible else 0

        # Inverse: compliance posture (higher = better)
        compliance_score = max(0, 100 - overall_residual_pct)

        # Tier breakdown
        tier_counts = {"Low": 0, "Moderate": 0, "High": 0, "Critical": 0}
        for a in applicable:
            tier_name, _, _ = a.risk_tier
            if tier_name in tier_counts:
                tier_counts[tier_name] += 1

        # Domain-level scores
        domain_scores = self._compute_domain_scores()

        # Safeguard-level scores
        safeguard_scores = self._compute_safeguard_scores()

        # Completion rate (how many controls have been assessed > default)
        completion_rate = self._compute_completion_rate()

        # Critical findings count
        critical_findings = [
            a for a in applicable
            if a.risk_tier[0] in ("Critical", "High")
        ]

        return {
            "org_name": self.session.org_name,
            "assessment_date": self.session.assessment_date,
            "assessor_name": self.session.assessor_name,
            "total_controls": len(applicable),
            "total_inherent_risk": round(total_inherent, 1),
            "total_residual_risk": round(total_residual, 1),
            "risk_reduction": round(total_inherent - total_residual, 1),
            "risk_reduction_pct": round(
                (1 - total_residual / total_inherent) * 100 if total_inherent > 0 else 0, 1
            ),
            "overall_residual_pct": round(overall_residual_pct, 1),
            "compliance_score": round(compliance_score, 1),
            "tier_counts": tier_counts,
            "critical_count": tier_counts["Critical"],
            "high_count": tier_counts["High"],
            "moderate_count": tier_counts["Moderate"],
            "low_count": tier_counts["Low"],
            "domain_scores": domain_scores,
            "safeguard_scores": safeguard_scores,
            "completion_rate": completion_rate,
            "critical_findings": [a.control_id for a in critical_findings],
        }

    def _compute_domain_scores(self) -> dict[str, dict]:
        """Per-risk-domain aggregate residual risk."""
        domain_data: dict[str, dict] = {}
        for control in CONTROLS:
            assessment = self.session.assessments.get(control.id)
            if not assessment or assessment.not_applicable:
                continue
            domain = control.risk_domain.value
            if domain not in domain_data:
                domain_data[domain] = {"residual": 0.0, "inherent": 0.0, "count": 0}
            domain_data[domain]["residual"] += assessment.residual_risk
            domain_data[domain]["inherent"] += assessment.inherent_risk
            domain_data[domain]["count"] += 1

        result = {}
        for domain, data in domain_data.items():
            max_possible = data["count"] * 25.0
            result[domain] = {
                "residual_risk": round(data["residual"], 1),
                "inherent_risk": round(data["inherent"], 1),
                "count": data["count"],
                "residual_pct": round(data["residual"] / max_possible * 100 if max_possible else 0, 1),
            }
        return result

    def _compute_safeguard_scores(self) -> dict[str, dict]:
        """Per-safeguard-category scores."""
        result = {}
        for safeguard, controls in CONTROLS_BY_SAFEGUARD.items():
            relevant = [
                self.session.assessments.get(c.id)
                for c in controls
                if self.session.assessments.get(c.id)
                and not self.session.assessments.get(c.id).not_applicable
            ]
            if not relevant:
                continue
            total_residual = sum(a.residual_risk for a in relevant)
            total_inherent = sum(a.inherent_risk for a in relevant)
            max_possible = len(relevant) * 25.0
            result[safeguard.value] = {
                "control_count": len(relevant),
                "residual_risk": round(total_residual, 1),
                "inherent_risk": round(total_inherent, 1),
                "residual_pct": round(total_residual / max_possible * 100 if max_possible else 0, 1),
                "avg_maturity": round(
                    sum(self.session.assessments[c.id].maturity_score
                        for c in controls if c.id in self.session.assessments) / len(relevant), 2
                ),
            }
        return result

    def _compute_completion_rate(self) -> float:
        """Fraction of controls with assessor-provided notes or evidence."""
        if not self.session.assessments:
            return 0.0
        with_input = sum(
            1 for a in self.session.assessments.values()
            if a.notes.strip() or a.evidence_provided
        )
        return round(with_input / len(self.session.assessments) * 100, 1)

    # ── Gap analysis ──────────────────────────────────────────

    def identify_gaps(self, min_maturity: int = 3) -> list[dict]:
        """
        Identify controls falling below minimum acceptable maturity.

        Parameters
        ----------
        min_maturity : Target minimum maturity level (default 3 = Defined)

        Returns
        -------
        List of gap records sorted by residual risk (highest first)
        """
        gaps = []
        for control in CONTROLS:
            assessment = self.session.assessments.get(control.id)
            if not assessment or assessment.not_applicable:
                continue
            if assessment.maturity_score < min_maturity:
                tier_name, tier_color, tier_action = assessment.risk_tier
                gaps.append({
                    "control_id": control.id,
                    "safeguard": control.safeguard.value,
                    "standard": control.standard,
                    "specification": control.specification,
                    "cfr_citation": control.specification_cfr,
                    "designation": control.designation.value,
                    "risk_domain": control.risk_domain.value,
                    "current_maturity": assessment.maturity_score,
                    "maturity_label": MATURITY_LABELS[assessment.maturity_score],
                    "target_maturity": min_maturity,
                    "gap": min_maturity - assessment.maturity_score,
                    "inherent_risk": assessment.inherent_risk,
                    "residual_risk": round(assessment.residual_risk, 1),
                    "risk_tier": tier_name,
                    "risk_tier_color": tier_color,
                    "risk_tier_action": tier_action,
                    "likelihood": assessment.likelihood,
                    "impact": assessment.impact,
                    "remediation_guidance": control.remediation_guidance,
                    "nist_functions": [f.value for f in control.nist_functions],
                    "cis_controls": control.cis_controls,
                })
        gaps.sort(key=lambda x: x["residual_risk"], reverse=True)
        return gaps

    def required_controls_gaps(self) -> list[dict]:
        """Return gaps specifically on REQUIRED controls — highest regulatory exposure."""
        all_gaps = self.identify_gaps(min_maturity=1)  # any unimplemented
        return [g for g in all_gaps if g["designation"] == "Required"]

    # ── Remediation planning ──────────────────────────────────

    IMPLEMENTATION_COMPLEXITY = {
        # control_id → complexity rating
        # Low = documentation/policy only; Medium = configuration; High = procurement/deployment
        "AS-01": "High", "AS-02": "Medium", "AS-03": "Low", "AS-04": "Medium",
        "AS-05": "Low", "AS-06": "Medium", "AS-07": "Low", "AS-08": "Low",
        "AS-09": "Medium", "AS-10": "Medium", "AS-11": "Low", "AS-12": "Low",
        "AS-13": "High", "AS-14": "Medium", "AS-15": "Medium", "AS-16": "Medium",
        "AS-17": "Medium", "AS-18": "Medium", "AS-19": "Low", "AS-20": "Low",
        "AS-21": "Low", "AS-22": "Medium", "AS-23": "Low", "PS-01": "Low",
        "PS-02": "Medium", "PS-03": "Low", "PS-04": "Low", "PS-05": "Low",
        "PS-06": "Low", "PS-07": "Low", "PS-08": "Low", "PS-09": "Medium",
        "TS-01": "Medium", "TS-02": "Low", "TS-03": "Low", "TS-04": "High",
        "TS-05": "High", "TS-06": "Medium", "TS-07": "Medium", "TS-08": "Medium",
        "TS-09": "Medium",
    }

    COMPLEXITY_ORDER = {"Low": 1, "Medium": 2, "High": 3}

    def generate_remediation_plan(self) -> list[dict]:
        """
        Generate a prioritized remediation action plan.

        Prioritization algorithm:
          1. Critical risk tier first, then High, Moderate, Low
          2. Within same tier: Required controls before Addressable
          3. Within same designation: lower complexity first (quick wins)

        Returns a list of action items with 30/60/90-day milestone assignments.
        """
        gaps = self.identify_gaps(min_maturity=3)  # target Defined maturity
        if not gaps:
            return []

        tier_order = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3}
        desig_order = {"Required": 0, "Addressable": 1}

        for item in gaps:
            item["complexity"] = self.IMPLEMENTATION_COMPLEXITY.get(
                item["control_id"], "Medium"
            )
            item["complexity_order"] = self.COMPLEXITY_ORDER.get(item["complexity"], 2)

        gaps.sort(key=lambda x: (
            tier_order.get(x["risk_tier"], 9),
            desig_order.get(x["designation"], 1),
            x["complexity_order"],
        ))

        # Assign milestones
        for i, item in enumerate(gaps):
            if item["risk_tier"] == "Critical":
                item["milestone"] = "Immediate (0–30 days)"
                item["milestone_order"] = 0
            elif item["risk_tier"] == "High":
                item["milestone"] = "Short-Term (30–90 days)"
                item["milestone_order"] = 1
            elif item["risk_tier"] == "Moderate":
                item["milestone"] = "Medium-Term (90–180 days)"
                item["milestone_order"] = 2
            else:
                item["milestone"] = "Annual Plan (180–365 days)"
                item["milestone_order"] = 3

            item["priority_rank"] = i + 1

        return gaps

    # ── Risk register ─────────────────────────────────────────

    def build_risk_register(self) -> list[dict]:
        """
        Full risk register: all assessed controls with scoring details.
        Suitable for export to Excel or inclusion in official SRA documentation.
        """
        register = []
        for control in CONTROLS:
            assessment = self.session.assessments.get(control.id)
            if not assessment:
                continue
            tier_name, tier_color, tier_action = assessment.risk_tier
            register.append({
                "Control ID": control.id,
                "Safeguard": control.safeguard.value,
                "Standard": control.standard,
                "CFR Citation": control.specification_cfr,
                "Specification": control.specification,
                "Designation": control.designation.value,
                "Risk Domain": control.risk_domain.value,
                "NIST Functions": ", ".join(f.value for f in control.nist_functions),
                "CIS Controls": ", ".join(control.cis_controls),
                "Maturity Score": assessment.maturity_score,
                "Maturity Level": MATURITY_LABELS[assessment.maturity_score],
                "Likelihood": assessment.likelihood,
                "Likelihood Level": LIKELIHOOD_LABELS[assessment.likelihood],
                "Impact": assessment.impact,
                "Impact Level": IMPACT_LABELS[assessment.impact],
                "Inherent Risk": round(assessment.inherent_risk, 1),
                "Control Effectiveness": f"{assessment.control_effectiveness * 100:.0f}%",
                "Residual Risk": round(assessment.residual_risk, 1),
                "Risk Tier": tier_name,
                "Required Action": tier_action,
                "N/A": assessment.not_applicable,
                "Assessor Notes": assessment.notes,
                "Evidence Items": "; ".join(assessment.evidence_provided),
            })
        return register

    # ── Helpers ───────────────────────────────────────────────

    def _empty_summary(self) -> dict:
        return {
            "org_name": self.session.org_name,
            "total_controls": 0,
            "total_residual_risk": 0,
            "compliance_score": 0,
            "tier_counts": {"Low": 0, "Moderate": 0, "High": 0, "Critical": 0},
            "domain_scores": {},
            "safeguard_scores": {},
            "completion_rate": 0,
            "critical_findings": [],
        }


# ─────────────────────────────────────────────────────────────
#  Convenience function
# ─────────────────────────────────────────────────────────────

def create_new_assessment(
    org_name: str,
    org_type: str = "community_hospital",
    assessor_name: str = "",
) -> SRASession:
    """Create and initialize a new SRA session with profile defaults."""
    session = SRASession(
        org_name=org_name,
        org_type=org_type,
        assessor_name=assessor_name,
        assessment_date=datetime.today().strftime("%Y-%m-%d"),
    )
    session.initialize_defaults()
    return session
