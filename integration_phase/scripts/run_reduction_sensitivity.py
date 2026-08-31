#!/usr/bin/env python3
"""Reducer replay helper.

This module provides shared reduction functions for
`run_corrected_reduction_sensitivity.py`. Its standalone replay does not
recompute GraphDB retrieval or pool-relative criteria and is not the corrected
selection-sensitivity experiment.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
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
from reduce_generated_playbooks import aggregate_manifest, reduce_items, scenario_key


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay generated-reduction sensitivity from ranked reduction report and candidate tables."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument("--mode", default="augmented-reduced")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("results/generated_repository/generated_playbooks_manifest.csv"),
    )
    parser.add_argument(
        "--reduction-report",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/reduction_report.csv"
        ),
        help=(
            "Compact reducer report used when --manifest is unavailable. "
            "It preserves every field needed to replay reduction caps."
        ),
    )
    parser.add_argument(
        "--strategy",
        choices=["top-risk", "diverse", "pareto", "hybrid"],
        default="hybrid",
    )
    parser.add_argument(
        "--per-scenario",
        type=int,
        nargs="+",
        default=[5, 10, 15, 25, 50],
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path(
            "results/evaluation/corrected/reduction_sensitivity/"
            "reducer_only_replay.csv"
        ),
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


def items_from_reduction_report(path: Path) -> dict[str, dict[str, Any]]:
    playbooks: dict[str, dict[str, Any]] = {}
    for row in read_csv_dicts(path):
        playbook_id = row.get("playbook_id", "").strip()
        if not playbook_id:
            continue
        signature_parts = row.get("semantic_signature", "").split("|")
        signature_parts.extend([""] * (5 - len(signature_parts)))
        attacks, cves, d3fend, artifacts, phases = (
            {value for value in part.split(";") if value}
            for part in signature_parts[:5]
        )
        risk_value = (
            row.get("risk_reduction_pct")
            if row.get("risk_reduction_pct") not in {None, ""}
            else row.get("risk_reduction")
        )
        playbooks[playbook_id] = {
            "playbook_id": playbook_id,
            "rows": [],
            "source": "generated",
            "source_case_id": "",
            "source_scenario_id": row.get("source_scenario_id", ""),
            "scenario_name": row.get("source_scenario_id", ""),
            "attack_path_id": "",
            "attack_techniques": attacks,
            "cves": cves,
            "d3fend_techniques": d3fend,
            "artifacts": artifacts,
            "phases": phases,
            "hosts": set(),
            "risk_reduction": to_float(risk_value, 0.0),
            "absolute_risk_reduction": to_float(
                row.get("absolute_risk_reduction", row.get("risk_reduction", "0")),
                0.0,
            ),
            "phase_completeness": to_float(row.get("phase_completeness"), 0.0),
            "action_count": int(to_float(row.get("action_count"), 0.0)),
        }
    return playbooks


def reduced_ids_by_scenario(
    manifest: Path,
    reduction_report: Path,
    strategy: str,
    limit: int,
) -> tuple[dict[str, set[str]], str]:
    if manifest.exists():
        playbooks = aggregate_manifest(read_csv_dicts(manifest))
        input_source = repo_display_path(manifest)
    elif reduction_report.exists():
        playbooks = items_from_reduction_report(reduction_report)
        input_source = repo_display_path(reduction_report)
    else:
        raise FileNotFoundError(
            f"Neither reducer manifest nor compact reduction report exists: "
            f"{manifest}, {reduction_report}"
        )
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in playbooks.values():
        grouped[scenario_key(item)].append(item)
    return (
        {
            scenario: {item["playbook_id"] for item in reduce_items(items, strategy, limit)}
            for scenario, items in grouped.items()
        },
        input_source,
    )


def combined_coverage(playbook_id: str, direct: dict[str, list[str]], inferred: dict[str, list[str]]) -> set[str]:
    return set(direct.get(playbook_id, [])) | set(inferred.get(playbook_id, []))


def average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    manifest = repo_path(args.manifest)
    reduction_report = repo_path(args.reduction_report)
    out_csv = repo_path(args.out_csv)
    selection_rows = rows_by_scenario(selection_path(evaluation_dir, args.mode))

    output_rows: list[dict[str, Any]] = []
    for limit in args.per_scenario:
        started = time.perf_counter()
        selected_generated_by_scenario, reduction_input = reduced_ids_by_scenario(
            manifest,
            reduction_report,
            args.strategy,
            limit,
        )
        selected_sources = Counter()
        selected_recalls: list[float] = []
        achievable_recalls: list[float] = []
        normalized_recalls: list[float] = []
        retained_generated_ids: set[str] = set()
        missing_scenarios: list[str] = []

        for scenario in DEFAULT_SCENARIOS:
            path = candidate_path(evaluation_dir, args.mode, scenario)
            if not path.exists():
                missing_scenarios.append(scenario)
                continue
            allowed = selected_generated_by_scenario.get(scenario.replace(" ", "_").replace(",", ""), set())
            if not allowed:
                allowed = selected_generated_by_scenario.get(scenario.replace(" ", "_"), set())
            retained_generated_ids.update(allowed)
            rows = read_csv_dicts(path)
            filtered = [
                row for row in rows
                if row.get("candidate_source") == "community" or row.get("playbook_id", "") in allowed
            ]
            if not filtered:
                missing_scenarios.append(scenario)
                continue
            direct = read_json(coverage_path(evaluation_dir, args.mode, scenario, "direct"))
            inferred = read_json(coverage_path(evaluation_dir, args.mode, scenario, "inferred"))
            selection = selection_rows.get(scenario, {})
            attack_count = int(to_float(selection.get("Scenario_Attack_Count"), 0.0))
            if attack_count <= 0:
                attack_count = len(set().union(*(combined_coverage(row.get("playbook_id", ""), direct, inferred) for row in filtered)))

            selected = min(
                filtered,
                key=lambda row: (
                    -to_float(row.get("total_score"), 0.0),
                    row.get("playbook_id", ""),
                ),
            )
            selected_sources[selected.get("candidate_source", "")] += 1
            selected_cov = combined_coverage(selected.get("playbook_id", ""), direct, inferred)
            achievable_cov = set().union(*(combined_coverage(row.get("playbook_id", ""), direct, inferred) for row in filtered))
            selected_recall = len(selected_cov) / attack_count if attack_count else 0.0
            achievable_recall = len(achievable_cov) / attack_count if attack_count else 0.0
            normalized_recall = selected_recall / achievable_recall if achievable_recall > 0 else 0.0
            selected_recalls.append(selected_recall)
            achievable_recalls.append(achievable_recall)
            normalized_recalls.append(normalized_recall)

        output_rows.append({
            "per_scenario": limit,
            "reduction_input": reduction_input,
            "status": "ok" if not missing_scenarios else "incomplete",
            "missing_scenarios": ";".join(missing_scenarios),
            "generated_candidates_retained": len(retained_generated_ids),
            "selected_generated_count": selected_sources.get("generated", 0),
            "selected_community_count": selected_sources.get("community", 0),
            "avg_combined_attack_recall": f"{average(selected_recalls):.6f}",
            "avg_achievable_combined_attack_recall": f"{average(achievable_recalls):.6f}",
            "avg_normalized_achievable_recall": f"{average(normalized_recalls):.6f}",
            "runtime_seconds": f"{time.perf_counter() - started:.3f}",
            "generated_playbooks_still_selected": str(selected_sources.get("generated", 0) > 0),
        })

    write_csv(
        out_csv,
        output_rows,
        [
            "per_scenario",
            "reduction_input",
            "status",
            "missing_scenarios",
            "generated_candidates_retained",
            "selected_generated_count",
            "selected_community_count",
            "avg_combined_attack_recall",
            "avg_achievable_combined_attack_recall",
            "avg_normalized_achievable_recall",
            "runtime_seconds",
            "generated_playbooks_still_selected",
        ],
    )
    print(f"Wrote reduction sensitivity to {out_csv}")


if __name__ == "__main__":
    main()
