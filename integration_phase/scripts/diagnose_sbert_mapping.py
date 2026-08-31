#!/usr/bin/env python3
"""Describe the submitted workshop SBERT mapping without asserting semantic accuracy."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import pandas as pd

from closed_loop_common import (
    execute_sparql,
    repo_display_path,
    repo_path,
    write_csv,
    write_json,
)


IRSO_NS = "http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#"
D3FEND_NS = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
DEFAULT_THRESHOLDS = (0.0, 0.2, 0.3, 0.4, 0.5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mapping-csv",
        type=Path,
        default=Path(
            "selection_phase/source/Playbook-defend-mapping/MainPart/"
            "playbook_defend_mapping.csv"
        ),
    )
    parser.add_argument(
        "--mapping-owl",
        type=Path,
        default=Path("selection_phase/source/GraphDB/playbook_step_defend_mapping.owl"),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(
            "selection_phase/source/Playbook-defend-mapping/MainPart/"
            "semantic_mapping_manifest.json"
        ),
    )
    parser.add_argument(
        "--endpoint",
        default="http://localhost:7200/repositories/incident-response",
    )
    parser.add_argument(
        "--out-diagnostics",
        type=Path,
        default=Path("results/evaluation/corrected/sbert_mapping_diagnostics.csv"),
    )
    parser.add_argument(
        "--out-cutoff-diagnostics",
        type=Path,
        default=Path(
            "results/evaluation/corrected/sbert_mapping_cutoff_diagnostics.csv"
        ),
    )
    parser.add_argument(
        "--out-metadata",
        type=Path,
        default=Path("results/evaluation/corrected/sbert_mapping_diagnostics_metadata.json"),
    )
    parser.add_argument(
        "--dominant-limit",
        type=int,
        default=20,
    )
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_fragment(value: object) -> str:
    if pd.isna(value):
        return ""
    text = str(value).strip()
    chars = [char if char.isalnum() or char in "_.-" else "_" for char in text]
    collapsed = "".join(chars)
    while "__" in collapsed:
        collapsed = collapsed.replace("__", "_")
    return collapsed.strip("_")


def fragment(uri: str) -> str:
    return str(uri).rsplit("#", 1)[-1]


def owl_links(path: Path) -> set[tuple[str, str]]:
    rdf_about = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about"
    rdf_resource = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource"
    links: set[tuple[str, str]] = set()
    root = ET.parse(path).getroot()
    for description in root:
        step = fragment(description.attrib.get(rdf_about, ""))
        for child in description:
            if child.tag == f"{{{IRSO_NS}}}usesDefensiveTechnique":
                technique = fragment(child.attrib.get(rdf_resource, ""))
                if step and technique:
                    links.add((step, technique))
    return links


def graphdb_links(endpoint: str) -> set[tuple[str, str]]:
    rows = execute_sparql(
        endpoint,
        f"""
PREFIX irso: <{IRSO_NS}>
SELECT ?step ?technique WHERE {{
  ?step irso:usesDefensiveTechnique ?technique .
}}
""",
        infer=False,
    )
    return {
        (fragment(row["step"]["value"]), fragment(row["technique"]["value"]))
        for row in rows
        if row.get("step") and row.get("technique")
    }


def record(
    rows: list[dict[str, Any]],
    record_type: str,
    metric: str,
    value: Any,
    *,
    count: Any = "",
    share: Any = "",
    threshold: Any = "",
    technique: str = "",
    status: str = "observed",
    notes: str = "",
) -> None:
    rows.append({
        "record_type": record_type,
        "metric": metric,
        "value": value,
        "count": count,
        "share": share,
        "threshold": threshold,
        "technique": technique,
        "status": status,
        "notes": notes,
    })


def main() -> int:
    args = parse_args()
    mapping_path = repo_path(args.mapping_csv)
    owl_path = repo_path(args.mapping_owl)
    manifest_path = repo_path(args.manifest)
    out_diagnostics = repo_path(args.out_diagnostics)
    out_cutoff_diagnostics = repo_path(args.out_cutoff_diagnostics)
    out_metadata = repo_path(args.out_metadata)

    assert (
        mapping_path
        and owl_path
        and out_diagnostics
        and out_cutoff_diagnostics
        and out_metadata
    )
    for path in (mapping_path, owl_path):
        if not path.exists():
            raise FileNotFoundError(path)

    frame = pd.read_csv(mapping_path)
    required = {
        "Playbook ID",
        "Step ID",
        "Best Matched D3FEND Technique",
        "Confidence Score",
    }
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"Mapping CSV missing columns: {sorted(missing)}")

    scores = pd.to_numeric(frame["Confidence Score"], errors="coerce")
    if scores.isna().any():
        raise ValueError("Mapping CSV contains non-numeric confidence scores")
    score_values = [float(value) for value in scores]
    techniques = frame["Best Matched D3FEND Technique"].fillna("").astype(str).str.strip()
    linked = ~techniques.str.lower().isin({"", "nan", "no match", "no_match", "no-match"})

    expected_links = {
        (
            f"Step_{safe_fragment(step_id)}",
            safe_fragment(technique),
        )
        for step_id, technique, is_linked in zip(frame["Step ID"], techniques, linked)
        if is_linked
    }
    expected_steps = {step for step, _technique in expected_links}
    owl_link_set = owl_links(owl_path)
    graphdb_link_set = graphdb_links(args.endpoint)
    graphdb_community_links = {
        pair for pair in graphdb_link_set if pair[0] in expected_steps
    }

    diagnostics: list[dict[str, Any]] = []
    record(diagnostics, "corpus", "mapping_rows", len(frame))
    record(diagnostics, "corpus", "unique_playbooks", frame["Playbook ID"].nunique())
    record(diagnostics, "corpus", "unique_steps", frame["Step ID"].nunique())
    record(diagnostics, "corpus", "linked_rows", int(linked.sum()))
    record(diagnostics, "corpus", "unlinked_rows", int((~linked).sum()))
    record(
        diagnostics,
        "corpus",
        "one_row_per_step",
        str(frame["Step ID"].nunique() == len(frame)),
    )

    quantiles = {
        "min": 0.0,
        "q01": 0.01,
        "q05": 0.05,
        "q10": 0.10,
        "q25": 0.25,
        "median": 0.50,
        "q75": 0.75,
        "q90": 0.90,
        "q95": 0.95,
        "q99": 0.99,
        "max": 1.0,
    }
    record(diagnostics, "confidence", "mean", mean(score_values))
    record(diagnostics, "confidence", "population_sd", pstdev(score_values))
    for label, probability in quantiles.items():
        record(diagnostics, "confidence", label, float(scores.quantile(probability)))
    for threshold in DEFAULT_THRESHOLDS[1:]:
        count = int((scores < threshold).sum())
        record(
            diagnostics,
            "confidence_threshold",
            "count_below",
            count,
            count=count,
            share=count / len(frame),
            threshold=threshold,
        )

    technique_counts = Counter(techniques[linked])
    for rank, (technique, count) in enumerate(
        sorted(technique_counts.items(), key=lambda item: (-item[1], item[0]))[
            : args.dominant_limit
        ],
        start=1,
    ):
        record(
            diagnostics,
            "technique_distribution",
            f"rank_{rank}",
            technique,
            count=count,
            share=count / int(linked.sum()) if linked.any() else math.nan,
            technique=technique,
            notes="Frequency is descriptive; it is not mapping-accuracy evidence.",
        )

    integrity_values = {
        "expected_csv_links": len(expected_links),
        "mapping_owl_links": len(owl_link_set),
        "graphdb_explicit_community_links": len(graphdb_community_links),
        "csv_owl_missing_links": len(expected_links - owl_link_set),
        "csv_owl_extra_links": len(owl_link_set - expected_links),
        "csv_graphdb_missing_links": len(expected_links - graphdb_community_links),
        "csv_graphdb_extra_links": len(graphdb_community_links - expected_links),
    }
    for metric, value in integrity_values.items():
        record(diagnostics, "integrity", metric, value)
    record(
        diagnostics,
        "validation",
        "expert_labelled_evaluation_available",
        False,
        notes=(
            "Confidence and integrity diagnostics do not establish semantic accuracy."
        ),
    )

    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path and manifest_path.exists()
        else {}
    )
    record(
        diagnostics,
        "provenance",
        "submitted_model_name",
        manifest.get("original_model_name", ""),
        status="recorded" if manifest.get("original_model_name") else "unrecorded",
    )
    record(
        diagnostics,
        "provenance",
        "submitted_model_revision",
        manifest.get("original_model_revision", ""),
        status=(
            "recorded"
            if manifest.get("original_model_revision_recorded", False)
            else "unrecorded"
        ),
    )
    record(
        diagnostics,
        "provenance",
        "submitted_runtime_configuration",
        manifest.get("original_runtime_configuration", ""),
        status=(
            "recorded"
            if manifest.get("original_runtime_configuration_recorded", False)
            else "unrecorded"
        ),
    )
    record(
        diagnostics,
        "provenance",
        "submitted_effective_threshold",
        manifest.get("minimum_confidence_used_by_submitted_artifact", ""),
    )

    sensitivity_rows: list[dict[str, Any]] = []
    for threshold in DEFAULT_THRESHOLDS:
        retained = linked & (scores >= threshold)
        retained_frame = frame.loc[retained]
        sensitivity_rows.append({
            "confidence_cutoff": threshold,
            "mapping_rows_retained": len(retained_frame),
            "mapping_rows_excluded": len(frame) - len(retained_frame),
            "mapping_share_retained": len(retained_frame) / len(frame),
            "unique_playbooks_with_link": retained_frame["Playbook ID"].nunique(),
            "unique_steps_with_link": retained_frame["Step ID"].nunique(),
            "unique_d3fend_techniques": retained_frame[
                "Best Matched D3FEND Technique"
            ].nunique(),
            "interpretation": (
                "descriptive link-retention diagnostic only; not threshold calibration "
                "and not semantic-accuracy evidence"
            ),
        })

    diagnostic_fields = [
        "record_type",
        "metric",
        "value",
        "count",
        "share",
        "threshold",
        "technique",
        "status",
        "notes",
    ]
    sensitivity_fields = list(sensitivity_rows[0])
    write_csv(out_diagnostics, diagnostics, diagnostic_fields)
    write_csv(out_cutoff_diagnostics, sensitivity_rows, sensitivity_fields)

    integrity_pass = all(
        integrity_values[key] == 0
        for key in (
            "csv_owl_missing_links",
            "csv_owl_extra_links",
            "csv_graphdb_missing_links",
            "csv_graphdb_extra_links",
        )
    )
    metadata = {
        "artifact_status": "paper evaluation descriptive diagnostics",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + " ".join(sys.argv),
        "endpoint": args.endpoint,
        "mapping_csv": repo_display_path(mapping_path),
        "mapping_csv_sha256": file_sha256(mapping_path),
        "mapping_owl": repo_display_path(owl_path),
        "mapping_owl_sha256": file_sha256(owl_path),
        "mapping_manifest": (
            repo_display_path(manifest_path)
            if manifest_path and manifest_path.exists()
            else None
        ),
        "mapping_manifest_sha256": (
            file_sha256(manifest_path)
            if manifest_path and manifest_path.exists()
            else None
        ),
        "integrity_status": "pass" if integrity_pass else "fail",
        "integrity": integrity_values,
        "confidence_interpretation": (
            "descriptive SBERT similarity score from the submitted mapping artifact; "
            "not a calibrated probability and not semantic-accuracy evidence"
        ),
        "manual_validation_available": False,
        "expert_validation_available": False,
        "selection_threshold_sensitivity_performed": False,
        "outputs": {
            "diagnostics": repo_display_path(out_diagnostics),
            "cutoff_diagnostics": repo_display_path(out_cutoff_diagnostics),
        },
    }
    write_json(out_metadata, metadata)

    print(f"Mapping rows: {len(frame)}")
    print(f"CSV/OWL/GraphDB integrity: {metadata['integrity_status']}")
    print(f"Wrote {out_diagnostics}")
    print(f"Wrote {out_cutoff_diagnostics}")
    return 0 if integrity_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
