"""tests/test_sra_engine.py — unit tests for the SRA engine."""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.controls import CONTROLS, CONTROLS_BY_ID, get_summary
from src.sra_engine import (
    ControlAssessment, SRASession, SRAEngine,
    create_new_assessment, MATURITY_LABELS,
)


@pytest.fixture(scope="module")
def session():
    s = create_new_assessment("Test Health System", "community_hospital", "Test Assessor")
    return s


@pytest.fixture(scope="module")
def engine(session):
    return SRAEngine(session)


class TestControlsDB:
    def test_controls_loaded(self):
        assert len(CONTROLS) > 0

    def test_all_ids_unique(self):
        ids = [c.id for c in CONTROLS]
        assert len(ids) == len(set(ids))

    def test_all_controls_have_cfr(self):
        for c in CONTROLS:
            assert c.specification_cfr.startswith("§"), f"{c.id} missing CFR citation"

    def test_summary_counts(self):
        s = get_summary()
        assert s["total_controls"] == s["administrative"] + s["physical"] + s["technical"]
        assert s["required"] + s["addressable"] == s["total_controls"]


class TestControlAssessment:
    def test_inherent_risk_calculation(self):
        a = ControlAssessment(control_id="AS-01", likelihood=4, impact=5)
        assert a.inherent_risk == 20.0

    def test_residual_risk_with_full_maturity(self):
        a = ControlAssessment(control_id="AS-01", likelihood=5, impact=5, maturity_score=5)
        assert a.residual_risk == 0.0

    def test_residual_risk_with_no_controls(self):
        a = ControlAssessment(control_id="AS-01", likelihood=5, impact=5, maturity_score=0)
        assert a.residual_risk == 25.0

    def test_residual_risk_partial_maturity(self):
        a = ControlAssessment(control_id="AS-01", likelihood=4, impact=5, maturity_score=3)
        # 20 * (1 - 0.55) = 9.0
        assert abs(a.residual_risk - 9.0) < 0.01

    def test_not_applicable_zero_risk(self):
        a = ControlAssessment(control_id="AS-09", not_applicable=True, likelihood=5, impact=5)
        assert a.residual_risk == 0.0

    def test_risk_tier_critical(self):
        a = ControlAssessment(control_id="AS-01", likelihood=5, impact=5, maturity_score=0)
        assert a.risk_tier[0] == "Critical"

    def test_risk_tier_low(self):
        a = ControlAssessment(control_id="AS-01", likelihood=2, impact=2, maturity_score=4)
        assert a.risk_tier[0] == "Low"


class TestSRASession:
    def test_session_initializes_all_controls(self, session):
        assert len(session.assessments) == len(CONTROLS)

    def test_all_control_ids_in_session(self, session):
        for control in CONTROLS:
            assert control.id in session.assessments

    def test_default_maturity_set(self, session):
        # community_hospital default is 2
        for a in session.assessments.values():
            assert a.maturity_score == 2


class TestSRAEngine:
    def test_summary_returns_dict(self, engine):
        summary = engine.compute_summary()
        assert isinstance(summary, dict)

    def test_summary_total_controls(self, engine):
        summary = engine.compute_summary()
        assert summary["total_controls"] == len(CONTROLS)

    def test_summary_has_domain_scores(self, engine):
        summary = engine.compute_summary()
        assert len(summary["domain_scores"]) > 0

    def test_summary_has_safeguard_scores(self, engine):
        summary = engine.compute_summary()
        assert "Administrative" in summary["safeguard_scores"]
        assert "Physical" in summary["safeguard_scores"]
        assert "Technical" in summary["safeguard_scores"]

    def test_compliance_score_in_range(self, engine):
        summary = engine.compute_summary()
        assert 0 <= summary["compliance_score"] <= 100

    def test_gap_analysis_finds_gaps(self, engine):
        # Default maturity is 2, target is 3 → should find gaps
        gaps = engine.identify_gaps(min_maturity=3)
        assert len(gaps) > 0

    def test_gap_analysis_sorted_by_risk(self, engine):
        gaps = engine.identify_gaps(min_maturity=3)
        risks = [g["residual_risk"] for g in gaps]
        assert risks == sorted(risks, reverse=True)

    def test_remediation_plan_ordered(self, engine):
        plan = engine.generate_remediation_plan()
        assert len(plan) > 0
        # All items should have a priority_rank
        assert all("priority_rank" in p for p in plan)
        ranks = [p["priority_rank"] for p in plan]
        assert ranks == list(range(1, len(plan) + 1))

    def test_risk_register_row_count(self, engine):
        register = engine.build_risk_register()
        assert len(register) == len(CONTROLS)

    def test_risk_register_has_required_fields(self, engine):
        register = engine.build_risk_register()
        required_fields = {"Control ID", "Residual Risk", "Risk Tier", "Maturity Score", "CFR Citation"}
        assert required_fields.issubset(set(register[0].keys()))
