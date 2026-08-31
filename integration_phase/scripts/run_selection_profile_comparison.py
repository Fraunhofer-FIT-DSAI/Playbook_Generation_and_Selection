#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    read_csv_dicts,
    repo_display_path,
    repo_path,
    to_float,
    write_csv,
)


PROFILES = ["closed-loop-balanced", "coverage-primary", "coverage-constrained"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay coverage-oriented selection profiles from candidate score tables."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument("--mode", default="augmented-reduced")
    parser.add_argument("--coverage-threshold", type=float, default=0.9)
    parser.add_argument(
        "--out-summary",
        type=Path,
        default=Path("results/evaluation/corrected/selection_profiles/profile_summary.csv"),
    )
    parser.add_argument(
        "--out-by-scenario",
        type=Path,
        default=Path("results/evaluation/corrected/selection_profiles/profile_by_scenario.csv"),
    )
    return parser.parse_args()


def candidate_path(evaluation_dir: Path, mode: str, scenario: str) -> Path:
    return evaluation_dir / mode / "candidate_scores_per_scenario" / f"{scenario}_candidate_scores.csv"


def coverage_path(evaluation_dir: Path, mode: str, scenario: str, kind: str) -> Path:
    return evaluation_dir / mode / "mcdm_scores_per_scenario" / f"{scenario}_{kind}_attack_coverage.json"


def selection_path(evaluation_dir: Path, mode: str) -> Path:
    return evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv"


def read_json(path: Path) -> Any:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def rows_by_scenario(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    return {
        row["Scenario"]: row
        for row in read_csv_dicts(path)
        if row.get("Scenario") and row.get("Scenario") != "Average"
    }


def combined_coverage(playbook_id: str, direct: dict[str, list[str]], inferred: dict[str, list[str]]) -> set[str]:
    return set(direct.get(playbook_id, [])) | set(inferred.get(playbook_id, []))


def average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_candidate(profile: str, rows: list[dict[str, str]], oracle: float, tau: float) -> tuple[dict[str, str], bool]:
    retained = rows
    threshold_satisfied = True
    if profile == "coverage-constrained":
        retained = [
            row for row in rows
            if to_float(row.get("combined_attack_recall"), 0.0) >= tau * oracle - 1e-12
        ]
        threshold_satisfied = bool(retained)
        if not retained:
            retained = rows

    if profile == "closed-loop-balanced":
        key = lambda row: (
            -to_float(row.get("total_score"), 0.0),
            row.get("playbook_id", ""),
        )
    elif profile == "coverage-primary":
        key = lambda row: (
            -to_float(row.get("combined_attack_recall"), 0.0),
            -to_float(row.get("total_score"), 0.0),
            int(to_float(row.get("action_count"), 10**9)),
            -to_float(row.get("raw_risk_reduction"), 0.0),
            row.get("playbook_id", ""),
        )
    else:
        key = lambda row: (
            -to_float(row.get("total_score"), 0.0),
            -to_float(row.get("combined_attack_recall"), 0.0),
            int(to_float(row.get("action_count"), 10**9)),
            -to_float(row.get("raw_risk_reduction"), 0.0),
            row.get("playbook_id", ""),
        )
    return min(retained, key=key), threshold_satisfied


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    out_summary = repo_path(args.out_summary)
    out_by_scenario = repo_path(args.out_by_scenario)
    selections = rows_by_scenario(selection_path(evaluation_dir, args.mode))

    by_scenario_rows: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for scenario in DEFAULT_SCENARIOS:
        path = candidate_path(evaluation_dir, args.mode, scenario)
        if not path.exists():
            continue
        rows = read_csv_dicts(path)
        direct = read_json(coverage_path(evaluation_dir, args.mode, scenario, "direct"))
        inferred = read_json(coverage_path(evaluation_dir, args.mode, scenario, "inferred"))
        selection = selections.get(scenario, {})
        attack_count = int(to_float(selection.get("Scenario_Attack_Count"), 0.0))
        if attack_count <= 0:
            attack_count = len(set().union(*(combined_coverage(row.get("playbook_id", ""), direct, inferred) for row in rows)))
        achievable = set().union(*(combined_coverage(row.get("playbook_id", ""), direct, inferred) for row in rows)) if rows else set()
        achievable_recall = len(achievable) / attack_count if attack_count else 0.0
        oracle_single = max((len(combined_coverage(row.get("playbook_id", ""), direct, inferred)) / attack_count for row in rows), default=0.0) if attack_count else 0.0

        scenario_profile_rows: list[dict[str, Any]] = []
        primary_id = selection.get("Top_MCDM_Playbook", "")
        for profile in PROFILES:
            if profile == "closed-loop-balanced" and primary_id:
                selected = next(
                    (
                        row
                        for row in rows
                        if row.get("playbook_id", "") == primary_id
                    ),
                    None,
                )
                if selected is None:
                    raise RuntimeError(
                        f"Primary winner {primary_id!r} is absent from {path}."
                    )
                threshold_satisfied = True
            else:
                selected, threshold_satisfied = select_candidate(
                    profile,
                    rows,
                    oracle_single,
                    args.coverage_threshold,
                )
            selected_cov = combined_coverage(selected.get("playbook_id", ""), direct, inferred)
            combined_recall = len(selected_cov) / attack_count if attack_count else 0.0
            normalized = combined_recall / achievable_recall if achievable_recall > 0 else 0.0
            row = {
                "profile": profile,
                "scenario": scenario,
                "selected_source": selected.get("candidate_source", ""),
                "selected_playbook_id": selected.get("playbook_id", ""),
                "combined_attack_recall": f"{combined_recall:.12f}",
                "achievable_combined_attack_recall": f"{achievable_recall:.12f}",
                "normalized_achievable_recall": f"{normalized:.12f}",
                "oracle_single_combined_attack_recall": f"{oracle_single:.12f}",
                "total_score": selected.get("total_score", ""),
                "action_count": selected.get("action_count", ""),
                "risk_reduction": selected.get("raw_risk_reduction", ""),
                "coverage_threshold": f"{args.coverage_threshold:.12f}",
                "coverage_threshold_satisfied": str(threshold_satisfied),
                "matches_primary_winner": str(
                    selected.get("playbook_id", "") == primary_id
                ),
            }
            scenario_profile_rows.append(row)

        baseline_row = next(
            row
            for row in scenario_profile_rows
            if row["profile"] == "closed-loop-balanced"
        )
        baseline_combined = to_float(
            baseline_row["combined_attack_recall"], 0.0
        )
        baseline_normalized = to_float(
            baseline_row["normalized_achievable_recall"], 0.0
        )
        for row in scenario_profile_rows:
            row["delta_combined_vs_closed_loop_balanced"] = (
                f"{to_float(row['combined_attack_recall'], 0.0) - baseline_combined:.12f}"
            )
            row["delta_normalized_vs_closed_loop_balanced"] = (
                f"{to_float(row['normalized_achievable_recall'], 0.0) - baseline_normalized:.12f}"
            )
            by_scenario_rows.append(row)
            grouped[row["profile"]].append(row)

    summary_rows = []
    baseline = average([to_float(row.get("normalized_achievable_recall"), 0.0) for row in grouped.get("closed-loop-balanced", [])])
    for profile in PROFILES:
        rows = grouped.get(profile, [])
        avg_normalized = average([to_float(row.get("normalized_achievable_recall"), 0.0) for row in rows])
        summary_rows.append({
            "profile": profile,
            "scenario_count": len(rows),
            "generated_selected_count": sum(1 for row in rows if row.get("selected_source") == "generated"),
            "community_selected_count": sum(1 for row in rows if row.get("selected_source") == "community"),
            "avg_combined_attack_recall": f"{average([to_float(row.get('combined_attack_recall'), 0.0) for row in rows]):.6f}",
            "avg_achievable_combined_attack_recall": f"{average([to_float(row.get('achievable_combined_attack_recall'), 0.0) for row in rows]):.6f}",
            "avg_normalized_achievable_recall": f"{avg_normalized:.6f}",
            "normalized_improvement_vs_closed_loop_balanced": f"{avg_normalized - baseline:.6f}",
            "avg_combined_improvement_vs_closed_loop_balanced": f"{average([to_float(row.get('delta_combined_vs_closed_loop_balanced'), 0.0) for row in rows]):.6f}",
        })

    fieldnames = [
        "profile",
        "scenario",
        "selected_source",
        "selected_playbook_id",
        "combined_attack_recall",
        "achievable_combined_attack_recall",
        "normalized_achievable_recall",
        "oracle_single_combined_attack_recall",
        "total_score",
        "action_count",
        "risk_reduction",
        "coverage_threshold",
        "coverage_threshold_satisfied",
        "matches_primary_winner",
        "delta_combined_vs_closed_loop_balanced",
        "delta_normalized_vs_closed_loop_balanced",
    ]
    summary_fieldnames = [
        "profile",
        "scenario_count",
        "generated_selected_count",
        "community_selected_count",
        "avg_combined_attack_recall",
        "avg_achievable_combined_attack_recall",
        "avg_normalized_achievable_recall",
        "normalized_improvement_vs_closed_loop_balanced",
        "avg_combined_improvement_vs_closed_loop_balanced",
    ]
    write_csv(out_by_scenario, by_scenario_rows, fieldnames)
    write_csv(out_summary, summary_rows, summary_fieldnames)
    metadata_path = out_summary.with_name(out_summary.stem + "_metadata.json")
    candidate_files = [
        candidate_path(evaluation_dir, args.mode, scenario)
        for scenario in DEFAULT_SCENARIOS
    ]
    metadata = {
        "result_state": "paper evaluation",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + shlex.join(sys.argv),
        "mode": args.mode,
        "coverage_threshold": args.coverage_threshold,
        "source_candidate_files": [
            {
                "path": repo_display_path(path),
                "sha256": file_sha256(path),
            }
            for path in candidate_files
        ],
        "summary": repo_display_path(out_summary),
        "summary_sha256": file_sha256(out_summary),
        "by_scenario": repo_display_path(out_by_scenario),
        "by_scenario_sha256": file_sha256(out_by_scenario),
        "closed_loop_tie_policy": "highest total_score, then lexicographically smallest playbook_id",
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote coverage profile summary to {out_summary}")
    print(f"Wrote coverage profile by-scenario results to {out_by_scenario}")


if __name__ == "__main__":
    main()
