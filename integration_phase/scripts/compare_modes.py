#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from closed_loop_common import DEFAULT_SCENARIOS, EVALUATION_MODES, read_csv_dicts, repo_path, write_csv


MODES = EVALUATION_MODES


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge closed-loop selection and recall results across modes."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation"),
        help="Directory containing community-only/generated-only/augmented outputs.",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("results/evaluation/closed_loop_comparison.csv"),
        help="Merged output CSV.",
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
    print(f"Wrote comparison table to {out_csv}")


if __name__ == "__main__":
    main()
