#!/usr/bin/env python3
"""Canonical score definitions and deterministic policies for selection experiments."""
from __future__ import annotations

from typing import Any


PROTOCOL_VERSION = "paper-evaluation-2026-07-27"
CRITERIA = ("DC", "DAC", "DTC", "TC", "RC", "CC", "AC")

COVERAGE_ONLY_WEIGHTS = {
    "DC": 0.50,
    "DAC": 0.50,
}

CLOSED_LOOP_BALANCED_WEIGHTS = {
    "DC": 0.25,
    "DAC": 0.20,
    "DTC": 0.20,
    "TC": 0.10,
    "RC": 0.15,
    "CC": 0.07,
    "AC": 0.03,
}

NEUTRAL_VALUE = 0.5
NEUTRAL_CONTEXT_CRITERIA = ("TC", "RC", "CC", "AC")
ZERO_IF_ABSENT_CRITERIA = ("DC", "DAC", "DTC")
TOP1_TIE_POLICY = "highest score, then lexicographically smallest stable playbook_id"

SCORE_DEFINITIONS = {
    "DC": (
        "Adjusted defensive-relation completeness: observed unique "
        "(ATT&CK technique, D3FEND relation) pairs divided by the scenario relation "
        "universe, multiplied by 1 - redundant_steps / matched_steps."
    ),
    "DAC": (
        "Distinct artifacts linked to the candidate through inferred ontology paths "
        "divided by the scenario artifact universe."
    ),
    "DTC": (
        "Direct ATT&CK techniques carried by candidate provenance and present in the "
        "target set, divided by target-set size."
    ),
    "TC": (
        "Topology/context match: 1 for a generated candidate whose source case or "
        "scenario matches the evaluated scenario, 0 for a known mismatch, otherwise missing."
    ),
    "RC": (
        "Candidate relative risk reduction RR=(R-Rs)/R divided by the largest "
        "available relative RR in the scenario candidate pool."
    ),
    "CC": (
        "Candidate CVEs intersecting scenario CVEs divided by the number of scenario CVEs."
    ),
    "AC": (
        "Inverse min-max normalized action count within the scenario candidate pool; "
        "1 is the smallest available count and 0 is the largest."
    ),
    "total_score": "Weighted sum of active criteria after applying the declared missing-value policy.",
}

RECALL_DEFINITIONS = {
    "direct_attack_recall": "Direct-provenance target coverage divided by target-set size.",
    "inferred_attack_recall": "Ontology-inferred target coverage divided by target-set size.",
    "combined_attack_recall": "Union of direct and inferred target coverage divided by target-set size.",
    "normalized_combined_attack_recall": (
        "Selected combined target coverage divided by the union coverage achievable by "
        "the scenario candidate pool."
    ),
}


def normalize_weights(weights: dict[str, float]) -> dict[str, float]:
    """Validate and normalize a criterion-weight mapping."""
    unknown = sorted(set(weights) - set(CRITERIA))
    if unknown:
        raise ValueError(f"Unknown selection criteria: {', '.join(unknown)}")
    if any(value < 0 for value in weights.values()):
        raise ValueError("Selection weights must be non-negative.")
    total = sum(weights.values())
    if total <= 0:
        raise ValueError("At least one selection criterion must have positive weight.")
    return {
        name: float(weights[name]) / total
        for name in CRITERIA
        if float(weights.get(name, 0.0)) > 0
    }


def protocol_manifest(
    *,
    weights: dict[str, float] | None = None,
    missing_context_policy: str = "neutral",
) -> dict[str, Any]:
    """Return a JSON-serializable statement of the selection contract."""
    return {
        "protocol_version": PROTOCOL_VERSION,
        "criteria_order": list(CRITERIA),
        "weights": normalize_weights(weights or CLOSED_LOOP_BALANCED_WEIGHTS),
        "score_definitions": SCORE_DEFINITIONS,
        "recall_definitions": RECALL_DEFINITIONS,
        "missing_context_policy": missing_context_policy,
        "neutral_value": NEUTRAL_VALUE,
        "neutral_context_criteria": list(NEUTRAL_CONTEXT_CRITERIA),
        "zero_if_absent_criteria": list(ZERO_IF_ABSENT_CRITERIA),
        "top1_tie_policy": TOP1_TIE_POLICY,
    }
