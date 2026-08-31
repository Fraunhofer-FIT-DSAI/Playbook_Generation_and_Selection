#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from collections import Counter
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select a small playbook portfolio per scenario to maximize combined ATT&CK coverage."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument("--mode", default="augmented-reduced")
    parser.add_argument("--portfolio-size", type=int, default=3)
    parser.add_argument(
        "--out-summary",
        type=Path,
        default=Path("results/evaluation/corrected/portfolio/portfolio_summary.csv"),
    )
    parser.add_argument(
        "--out-by-scenario",
        type=Path,
        default=Path("results/evaluation/corrected/portfolio/portfolio_by_scenario.csv"),
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


def combined_coverage_for(playbook_id: str, direct: dict[str, list[str]], inferred: dict[str, list[str]]) -> set[str]:
    return set(direct.get(playbook_id, [])) | set(inferred.get(playbook_id, []))


def average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    args = parse_args()
    if args.portfolio_size < 1 or args.portfolio_size > 3:
        raise ValueError("--portfolio-size must be between 1 and 3.")
    evaluation_dir = repo_path(args.evaluation_dir)
    out_summary = repo_path(args.out_summary)
    out_by_scenario = repo_path(args.out_by_scenario)
    selection_rows = rows_by_scenario(selection_path(evaluation_dir, args.mode))

    summary_rows: list[dict[str, Any]] = []
    detail_rows: list[dict[str, Any]] = []

    for scenario in DEFAULT_SCENARIOS:
        candidates_file = candidate_path(evaluation_dir, args.mode, scenario)
        if not candidates_file.exists():
            summary_rows.append({
                "scenario": scenario,
                "status": "missing_candidate_table",
            })
            continue

        rows = read_csv_dicts(candidates_file)
        direct = read_json(coverage_path(evaluation_dir, args.mode, scenario, "direct"))
        inferred = read_json(coverage_path(evaluation_dir, args.mode, scenario, "inferred"))
        selection = selection_rows.get(scenario, {})
        attack_count = int(to_float(selection.get("Scenario_Attack_Count"), 0.0))
        coverage_by_id = {
            row.get("playbook_id", ""): combined_coverage_for(row.get("playbook_id", ""), direct, inferred)
            for row in rows
            if row.get("playbook_id", "")
        }
        achievable = set().union(*coverage_by_id.values()) if coverage_by_id else set()
        if attack_count <= 0:
            attack_count = len(achievable)

        remaining = {row.get("playbook_id", ""): row for row in rows if row.get("playbook_id", "")}
        covered: set[str] = set()
        selected_rows: list[dict[str, str]] = []
        marginal_gains: list[int] = []

        while remaining and len(selected_rows) < args.portfolio_size:
            ranked = []
            for playbook_id, row in remaining.items():
                gain = len(coverage_by_id.get(playbook_id, set()) - covered)
                ranked.append((
                    -gain,
                    -to_float(row.get("total_score"), 0.0),
                    int(to_float(row.get("action_count"), 10**9)),
                    -to_float(row.get("raw_risk_reduction"), 0.0),
                    playbook_id,
                    row,
                ))
            negative_gain, _score, _action, _risk, playbook_id, row = min(ranked)
            gain = -negative_gain
            if gain <= 0:
                break
            selected_rows.append(row)
            marginal_gains.append(gain)
            covered |= coverage_by_id.get(playbook_id, set())
            remaining.pop(playbook_id, None)

        source_counts = Counter(row.get("candidate_source", "") for row in selected_rows)
        selected_ids = [row.get("playbook_id", "") for row in selected_rows]
        selected_sources = [row.get("candidate_source", "") for row in selected_rows]
        portfolio_recall = len(covered) / attack_count if attack_count else 0.0
        achievable_recall = len(achievable) / attack_count if attack_count else 0.0
        normalized = portfolio_recall / achievable_recall if achievable_recall > 0 else 0.0
        best_single_count = max(
            (len(coverage) for coverage in coverage_by_id.values()),
            default=0,
        )
        best_single_recall = (
            best_single_count / attack_count if attack_count else 0.0
        )
        primary_id = selection.get("Top_MCDM_Playbook", "")
        primary_coverage = coverage_by_id.get(primary_id, set())
        primary_recall = (
            len(primary_coverage) / attack_count if attack_count else 0.0
        )
        primary_normalized = (
            primary_recall / achievable_recall if achievable_recall > 0 else 0.0
        )
        generated_risks = [
            to_float(row.get("raw_risk_reduction"), 0.0)
            for row in selected_rows
            if row.get("candidate_source") == "generated" and str(row.get("raw_risk_reduction", "")).strip()
        ]
        total_action_count = sum(int(to_float(row.get("action_count"), 0.0)) for row in selected_rows)

        summary_rows.append({
            "scenario": scenario,
            "status": "ok",
            "portfolio_size": len(selected_rows),
            "selected_playbook_ids": ";".join(selected_ids),
            "selected_sources": ";".join(selected_sources),
            "generated_selected_count": source_counts.get("generated", 0),
            "community_selected_count": source_counts.get("community", 0),
            "portfolio_combined_attack_recall": f"{portfolio_recall:.12f}",
            "achievable_combined_attack_recall": f"{achievable_recall:.12f}",
            "portfolio_normalized_achievable_recall": f"{normalized:.12f}",
            "best_single_combined_attack_recall": f"{best_single_recall:.12f}",
            "closed_loop_balanced_combined_attack_recall": f"{primary_recall:.12f}",
            "closed_loop_balanced_normalized_recall": f"{primary_normalized:.12f}",
            "delta_combined_vs_closed_loop_balanced": f"{portfolio_recall - primary_recall:.12f}",
            "delta_normalized_vs_closed_loop_balanced": f"{normalized - primary_normalized:.12f}",
            "portfolio_not_below_best_member": str(
                portfolio_recall + 1e-12 >= best_single_recall
            ),
            "marginal_coverage_gain": ";".join(str(gain) for gain in marginal_gains),
            "total_action_count": total_action_count,
            "average_risk_reduction_generated": f"{average(generated_risks):.12f}" if generated_risks else "",
        })

        for rank, row in enumerate(selected_rows, start=1):
            detail_rows.append({
                "scenario": scenario,
                "rank": rank,
                "playbook_id": row.get("playbook_id", ""),
                "source": row.get("candidate_source", ""),
                "marginal_coverage_gain": marginal_gains[rank - 1],
                "combined_attack_count_after_selection": len(set().union(*(coverage_by_id.get(item.get("playbook_id", ""), set()) for item in selected_rows[:rank]))),
                "total_score": row.get("total_score", ""),
                "action_count": row.get("action_count", ""),
                "risk_reduction": row.get("raw_risk_reduction", ""),
            })

    valid_summary_rows = [
        row for row in summary_rows if row.get("status") == "ok"
    ]
    if valid_summary_rows:
        summary_rows.append(
            {
                "scenario": "Average",
                "status": "aggregate",
                "portfolio_size": (
                    f"{average([to_float(row.get('portfolio_size'), 0.0) for row in valid_summary_rows]):.6f}"
                ),
                "generated_selected_count": sum(
                    int(to_float(row.get("generated_selected_count"), 0.0))
                    for row in valid_summary_rows
                ),
                "community_selected_count": sum(
                    int(to_float(row.get("community_selected_count"), 0.0))
                    for row in valid_summary_rows
                ),
                "portfolio_combined_attack_recall": (
                    f"{average([to_float(row.get('portfolio_combined_attack_recall'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "achievable_combined_attack_recall": (
                    f"{average([to_float(row.get('achievable_combined_attack_recall'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "portfolio_normalized_achievable_recall": (
                    f"{average([to_float(row.get('portfolio_normalized_achievable_recall'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "best_single_combined_attack_recall": (
                    f"{average([to_float(row.get('best_single_combined_attack_recall'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "closed_loop_balanced_combined_attack_recall": (
                    f"{average([to_float(row.get('closed_loop_balanced_combined_attack_recall'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "closed_loop_balanced_normalized_recall": (
                    f"{average([to_float(row.get('closed_loop_balanced_normalized_recall'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "delta_combined_vs_closed_loop_balanced": (
                    f"{average([to_float(row.get('delta_combined_vs_closed_loop_balanced'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "delta_normalized_vs_closed_loop_balanced": (
                    f"{average([to_float(row.get('delta_normalized_vs_closed_loop_balanced'), 0.0) for row in valid_summary_rows]):.12f}"
                ),
                "portfolio_not_below_best_member": str(
                    all(
                        row.get("portfolio_not_below_best_member") == "True"
                        for row in valid_summary_rows
                    )
                ),
                "total_action_count": sum(
                    int(to_float(row.get("total_action_count"), 0.0))
                    for row in valid_summary_rows
                ),
            }
        )

    summary_fieldnames = [
        "scenario",
        "status",
        "portfolio_size",
        "selected_playbook_ids",
        "selected_sources",
        "generated_selected_count",
        "community_selected_count",
        "portfolio_combined_attack_recall",
        "achievable_combined_attack_recall",
        "portfolio_normalized_achievable_recall",
        "best_single_combined_attack_recall",
        "closed_loop_balanced_combined_attack_recall",
        "closed_loop_balanced_normalized_recall",
        "delta_combined_vs_closed_loop_balanced",
        "delta_normalized_vs_closed_loop_balanced",
        "portfolio_not_below_best_member",
        "marginal_coverage_gain",
        "total_action_count",
        "average_risk_reduction_generated",
    ]
    detail_fieldnames = [
        "scenario",
        "rank",
        "playbook_id",
        "source",
        "marginal_coverage_gain",
        "combined_attack_count_after_selection",
        "total_score",
        "action_count",
        "risk_reduction",
    ]
    write_csv(out_summary, summary_rows, summary_fieldnames)
    write_csv(out_by_scenario, detail_rows, detail_fieldnames)
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
        "portfolio_size_limit": args.portfolio_size,
        "algorithm": (
            "greedy maximum marginal combined ATT&CK coverage; ties by total "
            "score descending, action count ascending, relative risk metadata "
            "descending, playbook ID ascending"
        ),
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
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote portfolio summary to {out_summary}")
    print(f"Wrote portfolio by-scenario details to {out_by_scenario}")


if __name__ == "__main__":
    main()
