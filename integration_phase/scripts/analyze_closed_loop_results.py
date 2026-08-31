#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    EVALUATION_MODES,
    classify_playbook,
    read_csv_dicts,
    repo_display_path,
    repo_path,
    split_playbook_ids,
    to_float,
    write_csv,
    write_json,
)


PREFERRED_AUGMENTED_MODES = ["augmented-reduced", "augmented", "augmented-all"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diagnose why generated playbooks do or do not improve closed-loop results."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
        help="Directory containing selection/recall outputs.",
    )
    parser.add_argument(
        "--generated-steps-csv",
        dest="generated_steps_csv",
        type=Path,
        default=Path("results/generated_repository/export/generated_playbook_steps.csv"),
        help="CSV produced by export_generated_playbooks.py.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("results/evaluation/corrected/diagnostics"),
        help="Output directory for diagnostic summaries.",
    )
    parser.add_argument(
        "--generated-prefix",
        default="ma_",
        help="Generated playbook ID prefix.",
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
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def duplicate_step_stats(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"available": False}

    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    by_playbook: dict[str, list[dict[str, str]]] = defaultdict(list)
    step_ids = Counter()
    bad_command_examples = []
    for row in rows:
        by_playbook[row["playbook_id"]].append(row)
        step_ids[row["step_id"]] += 1
        first_word = str(row.get("command", "")).split(" ", 1)[0]
        if first_word in {"Analyz", "Disabl", "Restor"} and len(bad_command_examples) < 10:
            bad_command_examples.append({
                "playbook_id": row["playbook_id"],
                "step_id": row["step_id"],
                "command": row["command"],
            })

    duplicate_instances = 0
    playbooks_with_duplicates = 0
    for rows_for_playbook in by_playbook.values():
        keys = [
            (
                row.get("phase_label", ""),
                row.get("defensive_technique_id", ""),
                row.get("defense_artifact_id", ""),
                row.get("attack_technique_id", ""),
                row.get("host", ""),
            )
            for row in rows_for_playbook
        ]
        duplicates = len(keys) - len(set(keys))
        if duplicates:
            duplicate_instances += duplicates
            playbooks_with_duplicates += 1

    case_counts = Counter(row.get("source_case_id") or row.get("source_case", "") for row in rows)
    return {
        "available": True,
        "step_count": len(rows),
        "playbook_count": len(by_playbook),
        "source_case_count": len(case_counts),
        "duplicate_step_instances": duplicate_instances,
        "duplicate_step_ids": sum(1 for _step_id, count in step_ids.items() if count > 1),
        "playbooks_with_duplicate_steps": playbooks_with_duplicates,
        "bad_command_examples": bad_command_examples,
        "top_source_cases_by_step_count": case_counts.most_common(20),
    }


def first_playbook(value_text: str) -> str:
    ids = split_playbook_ids(value_text)
    return ids[0] if ids else ""


def candidate_rows(evaluation_dir: Path, mode: str, scenario: str) -> list[dict[str, str]]:
    path = evaluation_dir / mode / "candidate_scores_per_scenario" / f"{scenario}_candidate_scores.csv"
    return read_csv_dicts(path) if path.exists() else []


def best_by_source(rows: list[dict[str, str]], source: str, metric: str = "total_score") -> dict[str, str]:
    candidates = [row for row in rows if row.get("candidate_source") == source]
    if not candidates:
        return {}
    return min(
        candidates,
        key=lambda row: (-to_float(row.get(metric), -1.0), row.get("playbook_id", "")),
    )


def max_metric_by_source(rows: list[dict[str, str]], source: str, metric: str) -> float:
    values = [
        to_float(row.get(metric), 0.0)
        for row in rows
        if row.get("candidate_source") == source
    ]
    return max(values, default=0.0)


def loss_reasons(selected: dict[str, str], generated: dict[str, str], generated_count: int) -> list[str]:
    if generated_count == 0:
        return ["not_retrieved"]
    if not generated or selected.get("candidate_source") == "generated":
        return []

    reasons = []
    for criterion in ["DC", "DAC", "DTC", "TC", "RC", "CC"]:
        if to_float(generated.get(criterion), 0.0) < to_float(selected.get(criterion), 0.0):
            reasons.append(f"lower_{criterion}")
    if to_float(generated.get("AC"), 0.0) < to_float(selected.get("AC"), 0.0):
        reasons.append("action_penalty")
    missing = generated.get("missing_context_fields", "")
    if "direct_ATTCK_provenance" in missing:
        reasons.append("missing_ATTCK_provenance")
    if "topology_metadata" in missing or "TC" in missing:
        reasons.append("missing_topology_metadata")
    return reasons


def available_modes(evaluation_dir: Path) -> list[str]:
    return [
        mode for mode in EVALUATION_MODES
        if (evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv").exists()
    ]


def choose_augmented_mode(modes: list[str]) -> str:
    for mode in PREFERRED_AUGMENTED_MODES:
        if mode in modes:
            return mode
    return "augmented"


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    generated_steps_csv = repo_path(args.generated_steps_csv)
    out_dir = repo_path(args.out_dir)
    modes = available_modes(evaluation_dir)
    preferred_mode = choose_augmented_mode(modes)

    selections = {
        mode: rows_by_scenario(evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv")
        for mode in modes
    }
    recalls = {
        mode: rows_by_scenario(evaluation_dir / mode / f"ontology_coverage_metrics_{mode}.csv")
        for mode in modes
    }

    by_scenario_rows = []
    counters = Counter()

    augmented_all_selection = selections.get("augmented", selections.get("augmented-all", {}))
    augmented_reduced_selection = selections.get("augmented-reduced", {})

    for scenario in DEFAULT_SCENARIOS:
        selected_summary = selections.get(preferred_mode, {}).get(scenario, {})
        recall_summary = recalls.get(preferred_mode, {}).get(scenario, {})
        rows = candidate_rows(evaluation_dir, preferred_mode, scenario)
        selected_id = first_playbook(selected_summary.get("Top_MCDM_Playbook", ""))
        selected_candidate = next((row for row in rows if row.get("playbook_id") == selected_id), {})
        selected_source = selected_summary.get("candidate_source") or selected_summary.get("Top_Playbook_Source", "")

        best_community = best_by_source(rows, "community")
        best_generated = best_by_source(rows, "generated")
        generated_count = sum(1 for row in rows if row.get("candidate_source") == "generated")
        community_count = sum(1 for row in rows if row.get("candidate_source") == "community")
        reduced_count = to_float(selected_summary.get("reduced_generated_candidate_count"), 0.0)

        reasons = loss_reasons(selected_candidate, best_generated, generated_count)
        for reason in reasons:
            counters[reason] += 1

        selected_recall = to_float(
            recall_summary.get("combined_attack_recall") or selected_summary.get("combined_attack_recall") or recall_summary.get("Recall"),
            0.0,
        )
        selected_normalized_recall = to_float(
            recall_summary.get("normalized_combined_attack_recall")
            or selected_summary.get("normalized_combined_attack_recall"),
            0.0,
        )
        achievable_recall = to_float(
            recall_summary.get("achievable_combined_attack_recall")
            or selected_summary.get("achievable_combined_attack_recall"),
            0.0,
        )
        selected_score = to_float(selected_summary.get("total_score") or selected_summary.get("MCDM_Score"), 0.0)
        if selected_summary.get("MCDM_Score", "").endswith("%") and not selected_summary.get("total_score"):
            selected_score /= 100.0

        best_generated_direct = max_metric_by_source(rows, "generated", "direct_attack_recall")
        best_generated_inferred = max_metric_by_source(rows, "generated", "inferred_attack_recall")
        best_generated_combined = max_metric_by_source(rows, "generated", "combined_attack_recall")
        best_community_direct = max_metric_by_source(rows, "community", "direct_attack_recall")
        best_community_inferred = max_metric_by_source(rows, "community", "inferred_attack_recall")
        best_community_combined = max_metric_by_source(rows, "community", "combined_attack_recall")

        generated_retrieved = generated_count > 0
        generated_lost = generated_retrieved and selected_source != "generated"
        if generated_lost and best_generated_direct > to_float(selected_candidate.get("direct_attack_recall"), 0.0):
            counters["generated_improves_direct_recall_but_loses_mcdm"] += 1
        if generated_lost and to_float(best_generated.get("RC"), 0.0) > to_float(selected_candidate.get("RC"), 0.0):
            if to_float(best_generated.get("DC"), 0.0) < to_float(selected_candidate.get("DC"), 0.0) or to_float(best_generated.get("DAC"), 0.0) < to_float(selected_candidate.get("DAC"), 0.0):
                counters["generated_improves_risk_but_loses_coverage"] += 1
        oracle = max(
            (to_float(row.get("combined_attack_recall"), 0.0) for row in rows),
            default=0.0,
        )
        if oracle > selected_recall:
            counters["augmented_oracle_better_than_selected"] += 1
        if achievable_recall > selected_recall:
            counters["achievable_recall_better_than_selected"] += 1

        all_top = first_playbook(augmented_all_selection.get(scenario, {}).get("Top_MCDM_Playbook", ""))
        reduced_top = first_playbook(augmented_reduced_selection.get(scenario, {}).get("Top_MCDM_Playbook", ""))
        reduced_changes_source = False
        if all_top and reduced_top:
            reduced_changes_source = (
                classify_playbook(all_top, args.generated_prefix)
                != classify_playbook(reduced_top, args.generated_prefix)
            )
            if reduced_changes_source:
                counters["reduced_generated_pool_changes_selected_source"] += 1

        row = {
            "Scenario": scenario,
            "mode": preferred_mode,
            "selected_source": selected_source,
            "selected_playbook_id": selected_id,
            "selected_score": f"{selected_score:.6f}",
            "selected_recall": f"{selected_recall:.6f}",
            "selected_normalized_recall": f"{selected_normalized_recall:.6f}",
            "achievable_combined_recall": f"{achievable_recall:.6f}",
            "best_single_candidate_recall": f"{oracle:.6f}",
            "best_community_score": best_community.get("total_score", ""),
            "best_generated_score": best_generated.get("total_score", ""),
            "best_community_combined_recall": f"{best_community_combined:.6f}",
            "best_generated_combined_recall": f"{best_generated_combined:.6f}",
            "best_community_direct_recall": f"{best_community_direct:.6f}",
            "best_generated_direct_recall": f"{best_generated_direct:.6f}",
            "best_community_inferred_recall": f"{best_community_inferred:.6f}",
            "best_generated_inferred_recall": f"{best_generated_inferred:.6f}",
            "generated_candidate_count": generated_count,
            "community_candidate_count": community_count,
            "reduced_generated_candidate_count": int(reduced_count),
            "generated_candidates_retrieved": str(generated_retrieved),
            "loss_reasons": ";".join(reasons),
            "generated_improves_direct_recall_but_loses_mcdm": str(generated_lost and best_generated_direct > to_float(selected_candidate.get("direct_attack_recall"), 0.0)),
            "generated_improves_risk_but_loses_coverage": str(
                generated_lost
                and to_float(best_generated.get("RC"), 0.0) > to_float(selected_candidate.get("RC"), 0.0)
                and (
                    to_float(best_generated.get("DC"), 0.0) < to_float(selected_candidate.get("DC"), 0.0)
                    or to_float(best_generated.get("DAC"), 0.0) < to_float(selected_candidate.get("DAC"), 0.0)
                )
            ),
            "augmented_oracle_better_than_selected": str(oracle > selected_recall),
            "achievable_recall_better_than_selected": str(achievable_recall > selected_recall),
            "reduced_generated_pool_changes_selected_source": str(reduced_changes_source),
        }
        by_scenario_rows.append(row)

    export_stats = duplicate_step_stats(generated_steps_csv)
    summary = {
        "artifact_status": "paper evaluation",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + " ".join(sys.argv),
        "evaluation_dir": repo_display_path(evaluation_dir),
        "generated_steps_csv": repo_display_path(generated_steps_csv),
        "generated_steps_csv_sha256": (
            file_sha256(generated_steps_csv) if generated_steps_csv.exists() else None
        ),
        "available_modes": modes,
        "diagnosed_mode": preferred_mode,
        "scenario_count": len(by_scenario_rows),
        "selected_generated_count": sum(1 for row in by_scenario_rows if row["selected_source"] == "generated"),
        "generated_candidates_retrieved_count": sum(1 for row in by_scenario_rows if row["generated_candidates_retrieved"] == "True"),
        "loss_reason_counts": dict(counters),
        "generated_export": export_stats,
    }

    fieldnames = [
        "Scenario",
        "mode",
        "selected_source",
        "selected_playbook_id",
        "selected_score",
        "selected_recall",
        "selected_normalized_recall",
        "achievable_combined_recall",
        "best_single_candidate_recall",
        "best_community_score",
        "best_generated_score",
        "best_community_combined_recall",
        "best_generated_combined_recall",
        "best_community_direct_recall",
        "best_generated_direct_recall",
        "best_community_inferred_recall",
        "best_generated_inferred_recall",
        "generated_candidate_count",
        "community_candidate_count",
        "reduced_generated_candidate_count",
        "generated_candidates_retrieved",
        "loss_reasons",
        "generated_improves_direct_recall_but_loses_mcdm",
        "generated_improves_risk_but_loses_coverage",
        "augmented_oracle_better_than_selected",
        "achievable_recall_better_than_selected",
        "reduced_generated_pool_changes_selected_source",
    ]

    write_json(out_dir / "closed_loop_diagnostics_summary.json", summary)
    write_csv(out_dir / "closed_loop_diagnostics_by_scenario.csv", by_scenario_rows, fieldnames)

    print("Closed-loop diagnostics")
    print(f"- diagnosed mode: {preferred_mode}")
    print(f"- scenarios: {summary['scenario_count']}")
    print(f"- selected generated count: {summary['selected_generated_count']}")
    print(f"- generated candidates retrieved: {summary['generated_candidates_retrieved_count']}")
    print(f"- loss reasons: {summary['loss_reason_counts']}")
    print(f"Wrote diagnostics to {out_dir}")


if __name__ == "__main__":
    main()
