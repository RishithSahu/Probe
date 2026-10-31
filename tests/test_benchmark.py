"""Scoring needs real denominators and independent labels, never guesses."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.analysis.benchmark import Adjudication, GroundTruth, score_report


def truth(**updates):
    fields = dict(
        assessment_id="A-1", scope_id="S-1", tier="recon", authority_reference="organiser-manifest-reference",
        hosts=["HOST-A", "HOST-B"], services=["SERVICE-A", "SERVICE-B"], weaknesses=["W-1", "W-2"],
        adjudications={
            "F-1": Adjudication(verdict="true_positive", weakness_id="W-1", independently_verified=True),
            "F-2": Adjudication(verdict="false_positive"),
        },
    )
    fields.update(updates)
    return GroundTruth(**fields)


def report():
    return {
        "assessment_id": "A-1", "scope_id": "S-1", "data_integrity": {"contains_synthetic_data": False},
        "network_graph_overview": {"assets": [{"asset_id": "HOST-A", "services": [{"service_id": "SERVICE-A"}]}]},
        "findings_by_surface": {"web": [
            {"finding_id": "F-1", "status": "confirmed"}, {"finding_id": "F-2", "status": "suspected"},
        ]},
    }


def test_comparison_uses_planted_denominators_and_independent_adjudication():
    result = score_report(report(), truth())
    assert result["host_recall"] == result["service_recall"] == result["weakness_recall"] == 0.5
    assert result["false_positive_fraction"] == result["verified_fraction"] == 0.5
    assert result["missed_hosts"] == ["HOST-B"]
    assert result["missed_weaknesses"] == ["W-2"]
    assert result["scope_violations"] is None
    assert result["total_seconds"] is None


def test_unknown_label_prevents_false_precision_about_false_positives():
    manifest = truth(adjudications={"F-1": Adjudication(verdict="true_positive", weakness_id="W-1")})
    result = score_report(report(), manifest)
    assert result["false_positive_fraction"] is None
    assert result["verified_fraction"] is None
    assert result["adjudication_coverage"] == 0.5
    assert result["unreviewed_findings"] == ["F-2"]


@pytest.mark.parametrize("synthetic", [True, None])
def test_fixture_or_unspecified_integrity_cannot_be_scored_as_a_live_run(synthetic):
    data = report()
    data["data_integrity"]["contains_synthetic_data"] = synthetic
    with pytest.raises(ValueError, match="fixture-free"):
        score_report(data, truth())


def test_wrong_assessment_is_rejected():
    with pytest.raises(ValueError, match="same assessment"):
        score_report(report(), truth(assessment_id="A-OTHER"))


def test_duplicate_ground_truth_and_unknown_weakness_labels_are_rejected():
    with pytest.raises(ValidationError):
        truth(hosts=["HOST-A", "HOST-A"])
    with pytest.raises(ValidationError):
        truth(adjudications={"F-1": Adjudication(verdict="true_positive", weakness_id="UNKNOWN")})


def test_confirmed_label_alone_does_not_count_as_independently_verified():
    manifest = truth(adjudications={
        "F-1": Adjudication(verdict="true_positive", weakness_id="W-1"),
        "F-2": Adjudication(verdict="false_positive"),
    })
    assert score_report(report(), manifest)["verified_fraction"] == 0


def test_empty_denominators_remain_unknown():
    data = report()
    data["findings_by_surface"] = {}
    result = score_report(data, truth(hosts=[], services=[], weaknesses=[], adjudications={}))
    assert result["host_recall"] is None
    assert result["weakness_recall"] is None
    assert result["false_positive_fraction"] is None


def test_stale_adjudications_are_rejected():
    manifest = truth(adjudications={"OLD-FINDING": Adjudication(verdict="false_positive")})
    with pytest.raises(ValueError, match="absent"):
        score_report(report(), manifest)
