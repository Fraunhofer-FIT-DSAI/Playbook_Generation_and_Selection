#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    EVALUATION_MODES,
    read_csv_dicts,
    repo_display_path,
    repo_path,
    to_float,
    write_csv,
)


MODES = EVALUATION_MODES


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge closed-loop selection and recall results across modes."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
        help="Directory containing community-only/generated-only/augmented outputs.",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("results/evaluation/corrected/closed_loop_comparison.csv"),
        help="Merged output CSV.",
    )
    parser.add_argument(
        "--metadata-json",
        type=Path,
        help="Optional metadata sidecar; defaults beside --out-csv.",
    )
    return parser.parse_args()


def rows_by_scenario(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    return {
        row["Scenario"]: row
        for row in read_csv_dicts(path)
        if row.get("Scenario") and row.get("Scenario") != "Average"
    }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def numeric_mean(rows: list[dict[str, str]], field: str) -> str:
    values = [
        to_float(row.get(field), None)
        for row in rows
        if str(row.get(field, "")).strip()
    ]
    values = [value for value in values if value is not None]
    return "" if not values else f"{sum(values) / len(values):.6f}"


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)

    selections = {}
    recalls = {}
    for mode in MODES:
        selection_path = evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv"
        recall_path = evaluation_dir / mode / f"ontology_coverage_metrics_{mode}.csv"
        if not selection_path.exists() and not recall_path.exists():
            continue
        selections[mode] = rows_by_scenario(selection_path)
        recalls[mode] = rows_by_scenario(recall_path)

    merged_rows = []
    for scenario in DEFAULT_SCENARIOS:
        row = {"Scenario": scenario}
        for mode in MODES:
            if mode not in selections and mode not in recalls:
                continue
            selected = selections.get(mode, {}).get(scenario, {})
            recall = recalls.get(mode, {}).get(scenario, {})
            row[f"{mode}_top"] = selected.get("Top_MCDM_Playbook", "")
            row[f"{mode}_source"] = selected.get("Top_Playbook_Source", recall.get("Chosen Source", ""))
            row[f"{mode}_mcdm"] = selected.get("MCDM_Score", "")
            row[f"{mode}_defense_coverage"] = selected.get("Defense_Coverage", "")
            row[f"{mode}_artifact_coverage"] = selected.get("Artifact_Coverage", "")
            row[f"{mode}_candidate_count"] = selected.get("Candidate_Count", "")
            row[f"{mode}_generated_candidate_count"] = selected.get(
                "generated_candidate_count", ""
            )
            row[f"{mode}_community_candidate_count"] = selected.get(
                "community_candidate_count", ""
            )
            row[f"{mode}_selected_action_count"] = selected.get(
                "selected_action_count", ""
            )
            row[f"{mode}_selected_relative_risk_reduction"] = selected.get(
                "selected_risk_reduction", ""
            )
            row[f"{mode}_selected_cve_overlap"] = selected.get("CC", "")
            row[f"{mode}_recall"] = recall.get("Recall", "")
            row[f"{mode}_direct_recall"] = recall.get("direct_attack_recall", selected.get("direct_attack_recall", ""))
            row[f"{mode}_inferred_recall"] = recall.get("inferred_attack_recall", selected.get("inferred_attack_recall", ""))
            row[f"{mode}_combined_recall"] = recall.get("combined_attack_recall", selected.get("combined_attack_recall", ""))
            row[f"{mode}_achievable_recall"] = recall.get(
                "achievable_combined_attack_recall",
                selected.get("achievable_combined_attack_recall", ""),
            )
            row[f"{mode}_normalized_recall"] = recall.get(
                "normalized_combined_attack_recall",
                selected.get("normalized_combined_attack_recall", ""),
            )
            row[f"{mode}_achievable_attack_count"] = recall.get(
                "achievable_attack_technique_count",
                selected.get("achievable_attack_technique_count", ""),
            )
            row[f"{mode}_oracle_recall"] = recall.get("Max Recall (Candidate Pool)", "")
            row[f"{mode}_top_is_optimal"] = recall.get("Top is Optimal", "")
            row[f"{mode}_top_reaches_achievable"] = recall.get("Top Reaches Achievable Recall", "")

        row["augmented_changed_from_community"] = str(
            row.get("community-only_top", "") != row.get("augmented_top", "")
        )
        row["augmented_selected_generated"] = str(
            row.get("augmented_source", "") in {"generated", "mixed"}
        )
        row["augmented-reduced_selected_generated"] = str(
            row.get("augmented-reduced_source", "") in {"generated", "mixed"}
        )
        merged_rows.append(row)

    average_row = {"Scenario": "Average"}
    numeric_suffixes = (
        "candidate_count",
        "generated_candidate_count",
        "community_candidate_count",
        "selected_action_count",
        "selected_relative_risk_reduction",
        "selected_cve_overlap",
        "direct_recall",
        "inferred_recall",
        "combined_recall",
        "achievable_recall",
        "normalized_recall",
        "achievable_attack_count",
        "oracle_recall",
    )
    for mode in MODES:
        if mode not in selections and mode not in recalls:
            continue
        for suffix in numeric_suffixes:
            field = f"{mode}_{suffix}"
            average_row[field] = numeric_mean(merged_rows, field)
        sources = [row.get(f"{mode}_source", "") for row in merged_rows]
        average_row[f"{mode}_source"] = (
            f"generated={sum(source in {'generated', 'mixed'} for source in sources)};"
            f"community={sum(source == 'community' for source in sources)}"
        )
    merged_rows.append(average_row)

    fieldnames = ["Scenario"]
    for mode in MODES:
        if mode not in selections and mode not in recalls:
            continue
        fieldnames.extend([
            f"{mode}_top",
            f"{mode}_source",
            f"{mode}_mcdm",
            f"{mode}_defense_coverage",
            f"{mode}_artifact_coverage",
            f"{mode}_candidate_count",
            f"{mode}_generated_candidate_count",
            f"{mode}_community_candidate_count",
            f"{mode}_selected_action_count",
            f"{mode}_selected_relative_risk_reduction",
            f"{mode}_selected_cve_overlap",
            f"{mode}_recall",
            f"{mode}_direct_recall",
            f"{mode}_inferred_recall",
            f"{mode}_combined_recall",
            f"{mode}_achievable_recall",
            f"{mode}_normalized_recall",
            f"{mode}_achievable_attack_count",
            f"{mode}_oracle_recall",
            f"{mode}_top_is_optimal",
            f"{mode}_top_reaches_achievable",
        ])
    fieldnames.extend([
        "augmented_changed_from_community",
        "augmented_selected_generated",
        "augmented-reduced_selected_generated",
    ])

    out_csv = repo_path(args.out_csv)
    write_csv(out_csv, merged_rows, fieldnames)
    metadata_path = (
        repo_path(args.metadata_json)
        if args.metadata_json
        else out_csv.with_name(out_csv.stem + "_metadata.json")
    )
    assert metadata_path is not None
    source_files = []
    mode_protocols = {}
    for mode in sorted(set(selections) | set(recalls)):
        selection_path = evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv"
        if selection_path.exists():
            source_files.append(
                {
                    "path": repo_display_path(selection_path),
                    "sha256": file_sha256(selection_path),
                }
            )
        summary_path = evaluation_dir / mode / "selection_summary.json"
        if summary_path.exists():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            mode_protocols[mode] = {
                "scoring_profile": summary.get("scoring_profile"),
                "missing_context_policy": summary.get("missing_context_policy"),
                "protocol_version": summary.get("selection_protocol", {}).get(
                    "protocol_version"
                ),
                "weights": summary.get("weights", {}),
            }
            source_files.append(
                {
                    "path": repo_display_path(summary_path),
                    "sha256": file_sha256(summary_path),
                }
            )
    metadata = {
        "result_state": "paper evaluation",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + shlex.join(sys.argv),
        "evaluation_dir": repo_display_path(evaluation_dir),
        "output": repo_display_path(out_csv),
        "output_sha256": file_sha256(out_csv),
        "scenario_rows": len(DEFAULT_SCENARIOS),
        "aggregate_row": "Average",
        "mode_protocols": mode_protocols,
        "source_files": source_files,
        "recall_definitions": {
            "direct": "selected generated ATT&CK provenance intersect scenario target",
            "inferred": "selected artifact-D3FEND semantic associations intersect scenario target",
            "combined": "set union of direct and inferred target coverage",
            "achievable": "union coverage ceiling of the scenario candidate repository",
            "normalized": "selected combined coverage divided by achievable combined coverage",
        },
    }
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote comparison table to {out_csv}")


if __name__ == "__main__":
    main()
