#!/usr/bin/env python3
"""Audit whether the shipped SBERT-to-D3FEND mapping matches its declared threshold."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd

from closed_loop_common import repo_display_path, repo_path, write_json


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
        "--expected-threshold",
        type=float,
        default=float(os.getenv("MIN_D3FEND_MAPPING_CONFIDENCE", "0.0")),
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("results/evaluation/corrected/semantic_mapping_audit.json"),
    )
    return parser.parse_args()


def safe_fragment(value: object) -> str:
    text = "" if pd.isna(value) else str(value).strip()
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_artifact_key(path: Path) -> str:
    return repo_display_path(path)


def owl_links(path: Path) -> set[tuple[str, str]]:
    tree = ET.parse(path)
    rdf_about = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about"
    rdf_resource = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource"
    links: set[tuple[str, str]] = set()
    for description in tree.getroot():
        step = description.attrib.get(rdf_about, "").rsplit("#", 1)[-1]
        for element in description:
            if element.tag.endswith("}usesDefensiveTechnique"):
                technique = element.attrib.get(rdf_resource, "").rsplit("#", 1)[-1]
                if step and technique:
                    links.add((step, technique))
    return links


def main() -> int:
    args = parse_args()
    if not 0.0 <= args.expected_threshold <= 1.0:
        raise ValueError("--expected-threshold must be between 0 and 1.")

    mapping_path = repo_path(args.mapping_csv)
    owl_path = repo_path(args.mapping_owl)
    manifest_path = repo_path(args.manifest)
    out_path = repo_path(args.out_json)
    assert mapping_path is not None and owl_path is not None and out_path is not None

    if not mapping_path.exists() or not owl_path.exists():
        missing = [str(path) for path in (mapping_path, owl_path) if not path.exists()]
        raise FileNotFoundError(f"Missing semantic mapping artifacts: {', '.join(missing)}")

    frame = pd.read_csv(mapping_path)
    required = {"Step ID", "Best Matched D3FEND Technique", "Confidence Score"}
    missing_columns = sorted(required - set(frame.columns))
    if missing_columns:
        raise ValueError(f"Mapping CSV is missing columns: {', '.join(missing_columns)}")

    scores = pd.to_numeric(frame["Confidence Score"], errors="coerce")
    labels = frame["Best Matched D3FEND Technique"].fillna("").astype(str).str.strip()
    is_match = ~labels.str.lower().isin({"", "nan", "no match", "no_match", "no-match"})
    numeric = scores.notna()
    subthreshold_link_count = int((numeric & (scores < args.expected_threshold) & is_match).sum())
    above_threshold_no_match_count = int((numeric & (scores >= args.expected_threshold) & ~is_match).sum())
    linked_rows = int(is_match.sum())
    expected_links = {
        (f"Step_{safe_fragment(step_id)}", safe_fragment(technique))
        for step_id, technique, matched in zip(frame["Step ID"], labels, is_match)
        if matched and safe_fragment(step_id) and safe_fragment(technique)
    }
    actual_links = owl_links(owl_path)
    missing_owl_links = expected_links - actual_links
    extra_owl_links = actual_links - expected_links

    issues: list[str] = []
    unresolved: list[str] = []
    if int((~numeric).sum()):
        issues.append("mapping CSV contains non-numeric confidence scores")
    if subthreshold_link_count:
        issues.append("sub-threshold rows are exported as semantic links")
    if above_threshold_no_match_count:
        issues.append("at/above-threshold rows are marked No Match")
    if len(actual_links) != linked_rows:
        issues.append("OWL link count does not match linked CSV rows")
    if missing_owl_links or extra_owl_links:
        issues.append("GraphDB OWL step-to-technique links do not match the mapping CSV")

    manifest = None
    if manifest_path is not None and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        declared = manifest.get(
            "minimum_confidence",
            manifest.get("minimum_confidence_used_by_submitted_artifact"),
        )
        if declared is None or abs(float(declared) - args.expected_threshold) > 1e-12:
            issues.append("mapping manifest threshold differs from the expected threshold")
        declared_mapping_hash = (
            manifest.get("mapping_csv_sha256")
            or manifest.get("output_sha256")
        )
        if declared_mapping_hash != file_sha256(mapping_path):
            issues.append("mapping CSV hash differs from the mapping manifest")
        expected_manifest_counts = {
            "row_count": len(frame),
            "matched_count": linked_rows,
            "no_match_count": len(frame) - linked_rows,
        }
        for key, expected in expected_manifest_counts.items():
            if manifest.get(key) != expected:
                issues.append(f"mapping manifest {key} differs from the mapping CSV")
        weights = manifest.get("field_weights")
        if not manifest.get("model") or not isinstance(weights, dict):
            issues.append("mapping manifest is missing model or field weights")
        else:
            try:
                weights_sum = sum(float(value) for value in weights.values())
            except (TypeError, ValueError):
                issues.append("mapping manifest contains non-numeric field weights")
            else:
                if abs(weights_sum - 1.0) > 1e-12:
                    issues.append("mapping manifest field weights do not sum to one")
        if manifest.get("mapping_recomputed") is False and not manifest.get(
            "original_model_revision_recorded", False
        ):
            unresolved.append(
                "submitted mapping model revision was not recorded in the source snapshot"
            )
        if manifest.get("mapping_recomputed") is False and not manifest.get(
            "original_runtime_configuration_recorded", False
        ):
            unresolved.append(
                "submitted mapping runtime configuration was not recorded in the source snapshot"
            )

        owl_build = manifest.get("owl_build")
        if not isinstance(owl_build, dict):
            issues.append("mapping manifest is missing OWL build provenance")
        else:
            if owl_build.get("mapping_csv_sha256") != file_sha256(mapping_path):
                issues.append("OWL build used a different mapping CSV hash")
            if owl_build.get("link_count") != len(actual_links):
                issues.append("OWL build manifest link count differs from the OWL")
            output_hashes = owl_build.get("output_sha256", {})
            key = manifest_artifact_key(owl_path)
            if output_hashes.get(key) != file_sha256(owl_path):
                issues.append(f"OWL hash differs from the mapping manifest: {key}")
    else:
        issues.append("mapping provenance manifest is missing")

    report = {
        "status": "pass" if not issues else "fail",
        "reproduction_metadata_status": (
            "complete" if not unresolved else "incomplete_historical_record"
        ),
        "expected_threshold": args.expected_threshold,
        "row_count": len(frame),
        "numeric_score_count": int(numeric.sum()),
        "confidence_min": float(scores.min()) if numeric.any() else None,
        "confidence_mean": float(scores.mean()) if numeric.any() else None,
        "confidence_max": float(scores.max()) if numeric.any() else None,
        "below_threshold_count": int((numeric & (scores < args.expected_threshold)).sum()),
        "at_or_above_threshold_count": int((numeric & (scores >= args.expected_threshold)).sum()),
        "linked_csv_row_count": linked_rows,
        "subthreshold_link_count": subthreshold_link_count,
        "above_threshold_no_match_count": above_threshold_no_match_count,
        "expected_unique_csv_link_count": len(expected_links),
        "owl_uses_defensive_technique_count": len(actual_links),
        "matching_owl_link_count": len(expected_links & actual_links),
        "missing_owl_link_count": len(missing_owl_links),
        "extra_owl_link_count": len(extra_owl_links),
        "missing_owl_link_examples": sorted(missing_owl_links)[:10],
        "extra_owl_link_examples": sorted(extra_owl_links)[:10],
        "manifest_available": manifest is not None,
        "issues": issues,
        "unresolved": unresolved,
    }
    write_json(out_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
