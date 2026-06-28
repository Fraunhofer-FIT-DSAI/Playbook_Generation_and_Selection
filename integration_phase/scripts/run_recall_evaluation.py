#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    EVALUATION_MODES,
    GENERATED_REDUCED_MODES,
    canonical_mode,
    coverage_by_playbook,
    execute_filtered_scenario_direct_attack_query,
    execute_scenario_query,
    filter_rows,
    iter_scenario_paths,
    load_allowed_generated_ids,
    playbook_sources,
    read_csv_dicts,
    repo_path,
    split_playbook_ids,
    technique_ids_from_sparql,
    write_csv,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate selected playbooks by direct, inferred, and combined ATT&CK technique recall."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path("selection_phase/source"),
        help="Selection-phase source inside this repository.",
    )
    parser.add_argument(
        "--endpoint",
        default="http://localhost:7200/repositories/incident-response",
        help="GraphDB repository SPARQL endpoint.",
    )
    parser.add_argument(
        "--mode",
        choices=EVALUATION_MODES,
        default="augmented",
        help="Candidate pool used for oracle comparison.",
    )
    parser.add_argument(
        "--generated-prefix",
        default="ma_",
        help="Generated playbook ID prefix.",
    )
    parser.add_argument(
        "--reduced-manifest",
        type=Path,
        default=Path("results/generated_repository/reduced_generated_playbooks_manifest.csv"),
        help="Reduced generated manifest used by generated-reduced and augmented-reduced modes.",
    )
    parser.add_argument(
        "--allow-cross-scenario-generated",
        action="store_true",
        help=(
            "Allow generated playbooks from other scenario-conditioned cases to be considered. "
            "By default generated playbooks are restricted to the current scenario case."
        ),
    )
    parser.add_argument(
        "--disable-direct-attack-provenance",
        action="store_true",
        help="Ablation: ignore direct generated ATT&CK provenance during recall evaluation.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        help="Scenario name to evaluate. May be passed multiple times. Defaults to all canonical scenarios.",
    )
    parser.add_argument(
        "--selection-csv",
        type=Path,
        required=True,
        help="CSV produced by run_mcdm_selection.py.",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        required=True,
        help="Output recall metrics CSV.",
    )
    return parser.parse_args()


def recall(covered: set[str], true_ids: set[str]) -> float:
    if not true_ids:
        return 0.0
    return len(covered & true_ids) / len(true_ids)


def ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def union_for_selected(coverage: dict[str, set[str]], selected_playbooks: list[str]) -> set[str]:
    result: set[str] = set()
    for playbook in selected_playbooks:
        result |= coverage.get(playbook, set())
    return result


def main() -> None:
    args = parse_args()
    project_root = repo_path(args.project_root)
    selection_csv = repo_path(args.selection_csv)
    out_csv = repo_path(args.out_csv)
    canonical = canonical_mode(args.mode)
    reduced_manifest = repo_path(args.reduced_manifest)
    allowed_generated_ids = (
        load_allowed_generated_ids(reduced_manifest)
        if canonical in GENERATED_REDUCED_MODES
        else None
    )

    selection_rows = read_csv_dicts(selection_csv)
    selected_by_scenario = {
        row["Scenario"]: split_playbook_ids(row.get("Top_MCDM_Playbook", ""))
        for row in selection_rows
        if row.get("Scenario") and row.get("Scenario") != "Average"
    }

    evaluation_rows = []

    for scenario_name, sparql_path in iter_scenario_paths(project_root, args.scenario or DEFAULT_SCENARIOS):
        selected_playbooks = selected_by_scenario.get(scenario_name, [])
        true_ids = technique_ids_from_sparql(sparql_path)

        raw_inferred_rows = execute_scenario_query(args.endpoint, sparql_path)
        raw_direct_rows = execute_filtered_scenario_direct_attack_query(
            args.endpoint,
            sparql_path,
            args.mode,
            args.generated_prefix,
            scenario_name=scenario_name,
            match_generated_source_case=not args.allow_cross_scenario_generated,
            allowed_generated_ids=allowed_generated_ids,
        )
        if args.disable_direct_attack_provenance:
            raw_direct_rows = []
        inferred_rows = filter_rows(
            raw_inferred_rows,
            args.mode,
            args.generated_prefix,
            scenario_name=scenario_name,
            match_generated_source_case=not args.allow_cross_scenario_generated,
            allowed_generated_ids=allowed_generated_ids,
        )
        direct_rows = filter_rows(
            raw_direct_rows,
            args.mode,
            args.generated_prefix,
            scenario_name=scenario_name,
            match_generated_source_case=not args.allow_cross_scenario_generated,
            allowed_generated_ids=allowed_generated_ids,
        )

        inferred_coverage = coverage_by_playbook(inferred_rows, "attackId")
        direct_coverage = coverage_by_playbook(direct_rows, "attackId")
        all_playbooks = sorted(set(inferred_coverage) | set(direct_coverage))
        combined_coverage = {
            playbook: inferred_coverage.get(playbook, set()) | direct_coverage.get(playbook, set())
            for playbook in all_playbooks
        }

        achievable_direct = union_for_selected(direct_coverage, all_playbooks) & true_ids
        achievable_inferred = union_for_selected(inferred_coverage, all_playbooks) & true_ids
        achievable_combined = union_for_selected(combined_coverage, all_playbooks) & true_ids

        achievable_direct_recall = recall(achievable_direct, true_ids)
        achievable_inferred_recall = recall(achievable_inferred, true_ids)
        achievable_combined_recall = recall(achievable_combined, true_ids)

        selected_direct = union_for_selected(direct_coverage, selected_playbooks)
        selected_inferred = union_for_selected(inferred_coverage, selected_playbooks)
        selected_combined = selected_direct | selected_inferred

        selected_direct_recall = recall(selected_direct, true_ids)
        selected_inferred_recall = recall(selected_inferred, true_ids)
        selected_combined_recall = recall(selected_combined, true_ids)
        normalized_direct_recall = ratio(len(selected_direct & true_ids), len(achievable_direct))
        normalized_inferred_recall = ratio(len(selected_inferred & true_ids), len(achievable_inferred))
        normalized_combined_recall = ratio(len(selected_combined & true_ids), len(achievable_combined))

        best_combined_recall = 0.0
        best_direct_recall = 0.0
        best_inferred_recall = 0.0
        best_playbooks: list[str] = []
        for playbook in all_playbooks:
            combined_score = recall(combined_coverage.get(playbook, set()), true_ids)
            direct_score = recall(direct_coverage.get(playbook, set()), true_ids)
            inferred_score = recall(inferred_coverage.get(playbook, set()), true_ids)
            best_direct_recall = max(best_direct_recall, direct_score)
            best_inferred_recall = max(best_inferred_recall, inferred_score)
            if combined_score > best_combined_recall:
                best_combined_recall = combined_score
                best_playbooks = [playbook]
            elif combined_score == best_combined_recall:
                best_playbooks.append(playbook)

        evaluation_rows.append({
            "Scenario": scenario_name,
            "#Total Techniques": len(true_ids),
            "#Covered Techniques": len(selected_combined & true_ids),
            "Recall": f"{selected_combined_recall:.6f}",
            "direct_attack_recall": f"{selected_direct_recall:.6f}",
            "inferred_attack_recall": f"{selected_inferred_recall:.6f}",
            "combined_attack_recall": f"{selected_combined_recall:.6f}",
            "achievable_attack_technique_count": len(achievable_combined),
            "achievable_direct_attack_recall": f"{achievable_direct_recall:.6f}",
            "achievable_inferred_attack_recall": f"{achievable_inferred_recall:.6f}",
            "achievable_combined_attack_recall": f"{achievable_combined_recall:.6f}",
            "normalized_direct_attack_recall": f"{normalized_direct_recall:.6f}",
            "normalized_inferred_attack_recall": f"{normalized_inferred_recall:.6f}",
            "normalized_combined_attack_recall": f"{normalized_combined_recall:.6f}",
            "MCDM Chosen Playbook": ", ".join(selected_playbooks),
            "Chosen Source": playbook_sources(selected_playbooks, args.generated_prefix),
            "Top is Optimal": str(selected_combined_recall >= best_combined_recall - 1e-9),
            "Top Reaches Achievable Recall": str(selected_combined_recall >= achievable_combined_recall - 1e-9),
            "Max Recall (Candidate Pool)": f"{best_combined_recall:.6f}",
            "Max Direct Recall (Candidate Pool)": f"{best_direct_recall:.6f}",
            "Max Inferred Recall (Candidate Pool)": f"{best_inferred_recall:.6f}",
            "Achievable Recall (Candidate Pool)": f"{achievable_combined_recall:.6f}",
            "Best Recall Playbook": ", ".join(sorted(best_playbooks)),
            "Best Recall Source": playbook_sources(best_playbooks, args.generated_prefix),
        })

    write_csv(
        out_csv,
        evaluation_rows,
        [
            "Scenario",
            "#Total Techniques",
            "#Covered Techniques",
            "Recall",
            "direct_attack_recall",
            "inferred_attack_recall",
            "combined_attack_recall",
            "achievable_attack_technique_count",
            "achievable_direct_attack_recall",
            "achievable_inferred_attack_recall",
            "achievable_combined_attack_recall",
            "normalized_direct_attack_recall",
            "normalized_inferred_attack_recall",
            "normalized_combined_attack_recall",
            "MCDM Chosen Playbook",
            "Chosen Source",
            "Top is Optimal",
            "Top Reaches Achievable Recall",
            "Max Recall (Candidate Pool)",
            "Max Direct Recall (Candidate Pool)",
            "Max Inferred Recall (Candidate Pool)",
            "Achievable Recall (Candidate Pool)",
            "Best Recall Playbook",
            "Best Recall Source",
        ],
    )
    print(f"Wrote recall evaluation to {out_csv}")


if __name__ == "__main__":
    main()
