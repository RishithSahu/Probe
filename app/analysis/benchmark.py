"""Offline comparison with explicitly supplied, independently labelled truth.

This module never scans, labels a finding by guessing, or awards a score for
fixture results. Missing denominators/measurements produce null metrics.
Run with: python -m app.analysis.benchmark --help
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Adjudication(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["true_positive", "false_positive", "unresolved"]
    weakness_id: str | None = None
    independently_verified: bool = False


class GroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: str
    scope_id: str
    tier: Literal["recon", "breach", "deep"]
    authority_reference: str = Field(min_length=1)
    hosts: list[str]
    services: list[str]
    weaknesses: list[str]
    adjudications: dict[str, Adjudication] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_labels(self):
        for name in ("hosts", "services", "weaknesses"):
            values = getattr(self, name)
            if len(set(values)) != len(values) or any(not item.strip() for item in values):
                raise ValueError(f"{name} must contain distinct non-empty identifiers")
        for label in self.adjudications.values():
            if label.verdict == "true_positive":
                if label.weakness_id not in self.weaknesses:
                    raise ValueError("A true-positive label must reference a known planted weakness")
            elif label.weakness_id is not None or label.independently_verified:
                raise ValueError("Only true positives can reference a weakness or be independently verified")
        return self


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def score_report(report: dict, truth: GroundTruth) -> dict:
    if report.get("assessment_id") != truth.assessment_id or report.get("scope_id") != truth.scope_id:
        raise ValueError("Ground truth and report must describe the same assessment and scope")
    if report.get("data_integrity", {}).get("contains_synthetic_data") is not False:
        raise ValueError("Live scoring requires an explicit fixture-free data-integrity record")
    inventory = report.get("network_graph_overview") or {}
    hosts = {item["asset_id"] for item in inventory.get("assets", [])}
    services = {service["service_id"] for asset in inventory.get("assets", []) for service in asset.get("services", [])}
    findings = [item for group in report.get("findings_by_surface", {}).values() for item in group]
    finding_ids = [item["finding_id"] for item in findings]
    if len(set(finding_ids)) != len(finding_ids):
        raise ValueError("Report contains ambiguous duplicate finding IDs")
    if set(truth.adjudications) - set(finding_ids):
        raise ValueError("Ground-truth adjudications reference findings absent from the report")
    eligible = {item["finding_id"] for item in findings if item.get("status") != "rejected"}
    positive = {key for key, label in truth.adjudications.items() if key in eligible and label.verdict == "true_positive"}
    negative = {key for key, label in truth.adjudications.items() if key in eligible and label.verdict == "false_positive"}
    unreviewed = eligible - positive - negative
    found_weaknesses = {truth.adjudications[key].weakness_id for key in positive}
    verified = {key for key in positive if truth.adjudications[key].independently_verified}
    audit = report.get("scope_audit") or {}
    metrics = report.get("execution_metrics") or {}
    return {
        "assessment_id": truth.assessment_id, "scope_id": truth.scope_id,
        "tier": truth.tier, "ground_truth_reference": truth.authority_reference,
        "host_recall": _ratio(len(hosts & set(truth.hosts)), len(truth.hosts)),
        "service_recall": _ratio(len(services & set(truth.services)), len(truth.services)),
        "weakness_recall": _ratio(len(found_weaknesses), len(truth.weaknesses)),
        "false_positive_fraction": None if unreviewed else _ratio(len(negative), len(eligible)),
        "verified_fraction": None if unreviewed else _ratio(len(verified), len(eligible)),
        "adjudication_coverage": _ratio(len(positive | negative), len(eligible)),
        "unreviewed_findings": sorted(unreviewed),
        "missed_hosts": sorted(set(truth.hosts) - hosts),
        "missed_services": sorted(set(truth.services) - services),
        "missed_weaknesses": sorted(set(truth.weaknesses) - found_weaknesses),
        "scope_violations": audit.get("violations") if audit.get("independent") is True else None,
        "total_seconds": metrics.get("total_seconds"),
        "human_interventions": metrics.get("human_interventions"),
        "limitations": [
            "Ground truth and adjudications must be supplied independently; this tool does not authenticate the issuing authority.",
            "False-positive and verified fractions use all non-rejected reported findings as denominator; unknown labels prevent a complete rate.",
            "Missing audit, timing or intervention measurements remain unknown. No tier pass/fail is inferred.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    truth = GroundTruth.model_validate_json(args.truth.read_text(encoding="utf-8"))
    result = score_report(report, truth)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Offline benchmark comparison written.")


if __name__ == "__main__":
    main()
