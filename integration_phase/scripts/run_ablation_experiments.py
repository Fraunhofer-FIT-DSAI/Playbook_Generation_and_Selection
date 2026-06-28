#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    classify_playbook,
    read_csv_dicts,
    repo_path,
    to_float,
    write_csv,
)


CLOSED_LOOP_BALANCED_WEIGHTS = {
    "DC": 0.25,
    "DAC": 0.20,
    "DTC": 0.20,
    "TC": 0.10,
    "RC": 0.15,
    "CC": 0.07,
    "AC": 0.03,
}

ABLATIONS = [
    {
        "ablation_id": "A",
        "description": "community-only + coverage-only",
        "mode": "community-only",
        "scoring_profile": "coverage-only",
        "disabled": set(),
    },
    {
        "ablation_id": "B",
        "description": "augmented-reduced + coverage-only",
        "mode": "augmented-reduced",
        "scoring_profile": "coverage-only",
        "disabled": set(),
    },
    {
        "ablation_id": "C",
        "description": "augmented-reduced + closed-loop-balanced",
        "mode": "augmented-reduced",
        "scoring_profile": "closed-loop-balanced",
        "disabled": set(),
    },
    {
        "ablation_id": "D",
        "description": "augmented-reduced without direct ATT&CK provenance",
        "mode": "augmented-reduced",
        "scoring_profile": "closed-loop-balanced",
        "disabled": {"DTC", "direct-provenance"},
    },
    {
        "ablation_id": "E",
        "description": "augmented-reduced without risk criterion",
        "mode": "augmented-reduced",
        "scoring_profile": "closed-loop-balanced",
        "disabled": {"RC"},
    },
    {
        "ablation_id": "F",
        "description": "augmented-reduced without CVE criterion",
        "mode": "augmented-reduced",
        "scoring_profile": "closed-loop-balanced",
        "disabled": {"CC"},
    },
    {
        "ablation_id": "G",
        "description": "generated-reduced-only + closed-loop-balanced",
        "mode": "generated-reduced",
        "scoring_profile": "closed-loop-balanced",
        "disabled": set(),
    },
    {
        "ablation_id": "H",
        "description": "augmented-all + closed-loop-balanced",
        "mode": "augmented-all",
        "scoring_profile": "closed-loop-balanced",
        "disabled": set(),
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay closed-loop ablation selections from per-scenario candidate score tables."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation"),
        help="Evaluation output directory containing mode subdirectories.",
    )
    parser.add_argument(
        "--generated-prefix",
        default="ma_",
        help="Generated playbook ID prefix.",
    )
    parser.add_argument(
        "--out-summary",
        type=Path,
        default=Path("results/evaluation/ablation_summary.csv"),
    )
    parser.add_argument(
        "--out-by-scenario",
        type=Path,
        default=Path("results/evaluation/ablation_by_scenario.csv"),
    )
    return parser.parse_args()


def candidate_path(evaluation_dir: Path, mode: str, scenario: str) -> Path:
    return evaluation_dir / mode / "candidate_scores_per_scenario" / f"{scenario}_candidate_scores.csv"


def selection_path(evaluation_dir: Path, mode: str) -> Path:
    return evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv"


def rows_by_scenario(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    return {
        row["Scenario"]: row
        for row in read_csv_dicts(path)
        if row.get("Scenario") and row.get("Scenario") != "Average"
    }


def coverage_path(evaluation_dir: Path, mode: str, scenario: str, kind: str) -> Path:
    return evaluation_dir / mode / "mcdm_scores_per_scenario" / f"{scenario}_{kind}_attack_coverage.json"


def read_json(path: Path) -> Any:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def weights_for(scoring_profile: str, disabled: set[str]) -> dict[str, float]:
    if scoring_profile == "coverage-only":
        return {"DC": 0.5, "DAC": 0.5}
    weights = dict(CLOSED_LOOP_BALANCED_WEIGHTS)
    if "direct-provenance" in disabled:
        weights["DTC"] = 0.0
    for criterion in disabled:
        if criterion in weights:
            weights[criterion] = 0.0
    total = sum(weights.values())
    if total <= 0:
        return {}
    return {name: value / total for name, value in weights.items() if value > 0}


def score_candidate(row: dict[str, str], weights: dict[str, float], disabled: set[str]) -> float:
    score = 0.0
    for criterion, weight in weights.items():
        value = 0.0 if criterion in disabled else to_float(row.get(criterion), 0.0)
        score += value * weight
    return score


def coverage_for_candidate(
    playbook_id: str,
    direct_coverage: dict[str, list[str]],
    inferred_coverage: dict[str, list[str]],
    direct_enabled: bool,
) -> tuple[set[str], set[str], set[str]]:
    direct = set(direct_coverage.get(playbook_id, [])) if direct_enabled else set()
    inferred = set(inferred_coverage.get(playbook_id, []))
    return direct, inferred, direct | inferred


def union_coverage(
    playbook_ids: list[str],
    direct_coverage: dict[str, list[str]],
    inferred_coverage: dict[str, list[str]],
    direct_enabled: bool,
) -> tuple[set[str], set[str], set[str]]:
    direct: set[str] = set()
    inferred: set[str] = set()
    for playbook_id in playbook_ids:
        item_direct, item_inferred, _combined = coverage_for_candidate(
            playbook_id,
            direct_coverage,
            inferred_coverage,
            direct_enabled,
        )
        direct |= item_direct
        inferred |= item_inferred
    return direct, inferred, direct | inferred


def scenario_attack_count(rows: list[dict[str, str]], combined_union: set[str], selection_row: dict[str, str]) -> int:
    selected_count = int(to_float(selection_row.get("Scenario_Attack_Count"), 0.0))
    if selected_count > 0:
        return selected_count
    if rows:
        achievable = to_float(rows[0].get("achievable_combined_attack_recall"), 0.0)
        if achievable > 0:
            inferred_count = round(len(combined_union) / achievable)
            if inferred_count > 0:
                return inferred_count
    return len(combined_union)


def select_row(
    rows: list[dict[str, str]],
    weights: dict[str, float],
    direct_coverage: dict[str, list[str]],
    inferred_coverage: dict[str, list[str]],
    direct_enabled: bool,
    attack_count: int,
    disabled: set[str],
) -> tuple[dict[str, str], float, float]:
    scored = []
    for row in rows:
        playbook_id = row.get("playbook_id", "")
        _direct, _inferred, combined = coverage_for_candidate(
            playbook_id,
            direct_coverage,
            inferred_coverage,
            direct_enabled,
        )
        combined_recall = len(combined) / attack_count if attack_count else 0.0
        total_score = score_candidate(row, weights, disabled)
        scored.append((
            total_score,
            combined_recall,
            -int(to_float(row.get("action_count"), 10**9)),
            to_float(row.get("raw_risk_reduction"), 0.0),
            row.get("playbook_id", ""),
            row,
        ))
    if not scored:
        return {}, 0.0, 0.0
    total_score, combined_recall, _actions, _risk, _playbook, row = max(scored)
    return row, total_score, combined_recall


def numeric_average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    out_summary = repo_path(args.out_summary)
    out_by_scenario = repo_path(args.out_by_scenario)

    started = time.perf_counter()
    by_scenario_rows: list[dict[str, Any]] = []
    summary_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    selection_cache = {
        ablation["mode"]: rows_by_scenario(selection_path(evaluation_dir, ablation["mode"]))
        for ablation in ABLATIONS
    }

    for ablation in ABLATIONS:
        weights = weights_for(ablation["scoring_profile"], ablation["disabled"])
        for scenario in DEFAULT_SCENARIOS:
            path = candidate_path(evaluation_dir, ablation["mode"], scenario)
            if not path.exists():
                by_scenario_rows.append({
                    "ablation_id": ablation["ablation_id"],
                    "description": ablation["description"],
                    "mode": ablation["mode"],
                    "scenario": scenario,
                    "status": "missing_candidate_table",
                })
                continue
            rows = read_csv_dicts(path)
            direct_enabled = "direct-provenance" not in ablation["disabled"]
            direct_coverage = read_json(coverage_path(evaluation_dir, ablation["mode"], scenario, "direct"))
            inferred_coverage = read_json(coverage_path(evaluation_dir, ablation["mode"], scenario, "inferred"))
            if not direct_enabled:
                rows = [row for row in rows if row.get("playbook_id", "") in inferred_coverage]
            playbook_ids = [row.get("playbook_id", "") for row in rows if row.get("playbook_id")]
            achievable_direct, achievable_inferred, achievable_combined = union_coverage(
                playbook_ids,
                direct_coverage,
                inferred_coverage,
                direct_enabled,
            )
            attack_count = scenario_attack_count(
                rows,
                achievable_combined,
                selection_cache.get(ablation["mode"], {}).get(scenario, {}),
            )
            selected, total_score, _selection_combined = select_row(
                rows,
                weights,
                direct_coverage,
                inferred_coverage,
                direct_enabled,
                attack_count,
                ablation["disabled"],
            )
            if not selected:
                by_scenario_rows.append({
                    "ablation_id": ablation["ablation_id"],
                    "description": ablation["description"],
                    "mode": ablation["mode"],
                    "scenario": scenario,
                    "status": "no_candidates",
                })
                continue

            playbook_id = selected.get("playbook_id", "")
            selected_direct, selected_inferred, selected_combined = coverage_for_candidate(
                playbook_id,
                direct_coverage,
                inferred_coverage,
                direct_enabled,
            )
            direct_recall = len(selected_direct) / attack_count if attack_count else 0.0
            inferred_recall = len(selected_inferred) / attack_count if attack_count else 0.0
            combined_recall = len(selected_combined) / attack_count if attack_count else 0.0
            achievable_recall = len(achievable_combined) / attack_count if attack_count else 0.0
            normalized_recall = combined_recall / achievable_recall if achievable_recall > 0 else 0.0
            source_counts = Counter(row.get("candidate_source", "") for row in rows)
            row = {
                "ablation_id": ablation["ablation_id"],
                "description": ablation["description"],
                "mode": ablation["mode"],
                "scenario": scenario,
                "status": "ok",
                "scoring_profile": ablation["scoring_profile"],
                "disabled_criteria": ";".join(sorted(ablation["disabled"])),
                "selected_source": selected.get("candidate_source", ""),
                "selected_playbook_id": playbook_id,
                "combined_attack_recall": f"{combined_recall:.6f}",
                "direct_attack_recall": f"{direct_recall:.6f}",
                "inferred_attack_recall": f"{inferred_recall:.6f}",
                "achievable_combined_attack_recall": f"{achievable_recall:.6f}",
                "normalized_achievable_recall": f"{normalized_recall:.6f}",
                "total_score": f"{total_score:.6f}",
                "candidate_count": len(rows),
                "community_candidate_count": source_counts.get("community", 0),
                "generated_candidate_count": source_counts.get("generated", 0),
                "selected_action_count": selected.get("action_count", ""),
                "selected_risk_reduction": selected.get("raw_risk_reduction", ""),
                "source_case_id": selected.get("source_case_id", ""),
                "attack_path_id": selected.get("attack_path_id", ""),
            }
            by_scenario_rows.append(row)
            summary_groups[ablation["ablation_id"]].append(row)

    summary_rows: list[dict[str, Any]] = []
    for ablation in ABLATIONS:
        rows = summary_groups.get(ablation["ablation_id"], [])
        selected_sources = Counter(row.get("selected_source", "") for row in rows)
        missing = [
            row["scenario"]
            for row in by_scenario_rows
            if row.get("ablation_id") == ablation["ablation_id"] and row.get("status") != "ok"
        ]
        summary_rows.append({
            "ablation_id": ablation["ablation_id"],
            "description": ablation["description"],
            "mode": ablation["mode"],
            "scoring_profile": ablation["scoring_profile"],
            "disabled_criteria": ";".join(sorted(ablation["disabled"])),
            "status": "ok" if not missing else "incomplete",
            "scenario_count": len(rows),
            "missing_scenario_count": len(missing),
            "missing_scenarios": ";".join(missing),
            "generated_selected_count": selected_sources.get("generated", 0),
            "community_selected_count": selected_sources.get("community", 0),
            "avg_combined_attack_recall": f"{numeric_average([to_float(row.get('combined_attack_recall'), 0.0) for row in rows]):.6f}",
            "avg_direct_attack_recall": f"{numeric_average([to_float(row.get('direct_attack_recall'), 0.0) for row in rows]):.6f}",
            "avg_inferred_attack_recall": f"{numeric_average([to_float(row.get('inferred_attack_recall'), 0.0) for row in rows]):.6f}",
            "avg_achievable_combined_attack_recall": f"{numeric_average([to_float(row.get('achievable_combined_attack_recall'), 0.0) for row in rows]):.6f}",
            "avg_normalized_achievable_recall": f"{numeric_average([to_float(row.get('normalized_achievable_recall'), 0.0) for row in rows]):.6f}",
            "avg_total_score": f"{numeric_average([to_float(row.get('total_score'), 0.0) for row in rows]):.6f}",
            "avg_action_count": f"{numeric_average([to_float(row.get('selected_action_count'), 0.0) for row in rows if str(row.get('selected_action_count', '')).strip()]):.6f}",
            "avg_selected_risk_reduction": f"{numeric_average([to_float(row.get('selected_risk_reduction'), 0.0) for row in rows if str(row.get('selected_risk_reduction', '')).strip()]):.6f}",
            "runtime_seconds": f"{time.perf_counter() - started:.3f}",
        })

    by_scenario_fieldnames = [
        "ablation_id",
        "description",
        "mode",
        "scenario",
        "status",
        "scoring_profile",
        "disabled_criteria",
        "selected_source",
        "selected_playbook_id",
        "combined_attack_recall",
        "direct_attack_recall",
        "inferred_attack_recall",
        "achievable_combined_attack_recall",
        "normalized_achievable_recall",
        "total_score",
        "candidate_count",
        "community_candidate_count",
        "generated_candidate_count",
        "selected_action_count",
        "selected_risk_reduction",
        "source_case_id",
        "attack_path_id",
    ]
    summary_fieldnames = [
        "ablation_id",
        "description",
        "mode",
        "scoring_profile",
        "disabled_criteria",
        "status",
        "scenario_count",
        "missing_scenario_count",
        "missing_scenarios",
        "generated_selected_count",
        "community_selected_count",
        "avg_combined_attack_recall",
        "avg_direct_attack_recall",
        "avg_inferred_attack_recall",
        "avg_achievable_combined_attack_recall",
        "avg_normalized_achievable_recall",
        "avg_total_score",
        "avg_action_count",
        "avg_selected_risk_reduction",
        "runtime_seconds",
    ]
    write_csv(out_by_scenario, by_scenario_rows, by_scenario_fieldnames)
    write_csv(out_summary, summary_rows, summary_fieldnames)
    print(f"Wrote ablation summary to {out_summary}")
    print(f"Wrote ablation by-scenario results to {out_by_scenario}")


if __name__ == "__main__":
    main()
