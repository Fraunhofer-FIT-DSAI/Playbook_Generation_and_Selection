#!/usr/bin/env python3
"""Compare canonical, unreduced, and coverage-aware repository variants."""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
from typing import Any

import numpy as np

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    read_csv_dicts,
    repo_path,
    to_float,
    write_csv,
)


TOLERANCE = 1e-12
ALTERNATIVES = ("coverage_preserving", "marginal_coverage")
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--primary-evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument(
        "--unreduced-evaluation-dir",
        type=Path,
        default=Path(
            "results/evaluation/corrected/reduction_effect/unreduced"
        ),
    )
    parser.add_argument(
        "--canonical-reduction-report",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/reduction_report.csv"
        ),
    )
    parser.add_argument(
        "--alternative-root",
        type=Path,
        default=Path(
            "results/evaluation/corrected/reduction_alternatives"
        ),
    )
    parser.add_argument(
        "--out-reduction-effect",
        type=Path,
        default=Path(
            "results/evaluation/corrected/reduction_effect_by_scenario.csv"
        ),
    )
    parser.add_argument(
        "--out-alternative-by-scenario",
        type=Path,
        default=Path(
            "results/evaluation/corrected/reduction_alternative_by_scenario.csv"
        ),
    )
    parser.add_argument(
        "--out-alternative-summary",
        type=Path,
        default=Path(
            "results/evaluation/corrected/reduction_alternative_summary.csv"
        ),
    )
    parser.add_argument("--bootstrap-replicates", type=int, default=50000)
    parser.add_argument("--seed", type=int, default=20260729)
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def candidate_path(root: Path, mode: str, scenario: str) -> Path:
    return (
        root
        / mode
        / "candidate_scores_per_scenario"
        / f"{scenario}_candidate_scores.csv"
    )


def coverage_path(root: Path, mode: str, scenario: str, kind: str) -> Path:
    return (
        root
        / mode
        / "mcdm_scores_per_scenario"
        / f"{scenario}_{kind}_attack_coverage.json"
    )


def stable_best(rows: list[dict[str, str]]) -> dict[str, str]:
    if not rows:
        return {}
    return min(
        rows,
        key=lambda row: (
            -to_float(row.get("total_score"), 0.0),
            row.get("playbook_id", ""),
        ),
    )


def stable_highest_recall(rows: list[dict[str, str]]) -> dict[str, str]:
    if not rows:
        return {}
    return min(
        rows,
        key=lambda row: (
            -to_float(row.get("combined_attack_recall"), 0.0),
            -to_float(row.get("total_score"), 0.0),
            row.get("playbook_id", ""),
        ),
    )


def generated_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [row for row in rows if row.get("candidate_source") == "generated"]


def coverage_union(
    root: Path,
    mode: str,
    scenario: str,
    playbook_ids: set[str] | None = None,
) -> set[str]:
    direct = read_json(coverage_path(root, mode, scenario, "direct"))
    inferred = read_json(coverage_path(root, mode, scenario, "inferred"))
    all_ids = set(direct) | set(inferred)
    if playbook_ids is not None:
        all_ids &= playbook_ids
    union: set[str] = set()
    for playbook_id in all_ids:
        union |= set(direct.get(playbook_id, []))
        union |= set(inferred.get(playbook_id, []))
    return union


def first_metric(rows: list[dict[str, str]], name: str) -> float:
    return to_float(rows[0].get(name), 0.0) if rows else 0.0


def kept_ids(path: Path) -> set[str]:
    return {
        row.get("playbook_id", "")
        for row in read_csv_dicts(path)
        if row.get("kept") == "True"
    }


def reduction_effect_rows(
    primary_root: Path,
    unreduced_root: Path,
    reduction_report: Path,
) -> list[dict[str, Any]]:
    retained = kept_ids(reduction_report)
    output: list[dict[str, Any]] = []
    for scenario in DEFAULT_SCENARIOS:
        reduced_aug = read_csv_dicts(
            candidate_path(primary_root, "augmented-reduced", scenario)
        )
        reduced_gen = read_csv_dicts(
            candidate_path(primary_root, "generated-reduced", scenario)
        )
        full_aug = read_csv_dicts(
            candidate_path(unreduced_root, "augmented-all", scenario)
        )
        full_gen = read_csv_dicts(
            candidate_path(unreduced_root, "generated-all", scenario)
        )
        full_generated_in_aug = generated_rows(full_aug)
        reduced_generated_in_aug = generated_rows(reduced_aug)
        full_best_score = stable_best(full_generated_in_aug)
        reduced_best_score = stable_best(reduced_generated_in_aug)
        full_best_recall = stable_highest_recall(full_generated_in_aug)
        reduced_best_recall = stable_highest_recall(reduced_generated_in_aug)
        full_selected = stable_best(full_aug)
        reduced_selected = stable_best(reduced_aug)
        full_ids = {
            row.get("playbook_id", "") for row in full_generated_in_aug
        }
        reduced_ids = {
            row.get("playbook_id", "") for row in reduced_generated_in_aug
        }
        full_union = coverage_union(
            unreduced_root,
            "augmented-all",
            scenario,
            full_ids,
        )
        reduced_union = coverage_union(
            primary_root,
            "augmented-reduced",
            scenario,
            reduced_ids,
        )
        lost = full_union - reduced_union
        selected_full_id = full_selected.get("playbook_id", "")
        selected_reduced_id = reduced_selected.get("playbook_id", "")
        full_selected_recall = to_float(
            full_selected.get("combined_attack_recall"), 0.0
        )
        reduced_selected_recall = to_float(
            reduced_selected.get("combined_attack_recall"), 0.0
        )
        full_achievable = first_metric(
            full_aug, "achievable_combined_attack_recall"
        )
        reduced_achievable = first_metric(
            reduced_aug, "achievable_combined_attack_recall"
        )
        output.append(
            {
                "scenario_id": scenario,
                "unreduced_generated_candidate_count": len(full_generated_in_aug),
                "reduced_generated_candidate_count": len(
                    reduced_generated_in_aug
                ),
                "unreduced_highest_scoring_generated_id": full_best_score.get(
                    "playbook_id", ""
                ),
                "unreduced_highest_scoring_generated_score": full_best_score.get(
                    "total_score", ""
                ),
                "reduced_highest_scoring_generated_id": reduced_best_score.get(
                    "playbook_id", ""
                ),
                "reduced_highest_scoring_generated_score": reduced_best_score.get(
                    "total_score", ""
                ),
                "highest_scoring_generated_removed": str(
                    full_best_score.get("playbook_id", "") not in retained
                ),
                "unreduced_highest_recall_generated_id": full_best_recall.get(
                    "playbook_id", ""
                ),
                "unreduced_highest_generated_combined_recall": full_best_recall.get(
                    "combined_attack_recall", ""
                ),
                "reduced_highest_recall_generated_id": reduced_best_recall.get(
                    "playbook_id", ""
                ),
                "reduced_highest_generated_combined_recall": reduced_best_recall.get(
                    "combined_attack_recall", ""
                ),
                "highest_recall_generated_removed": str(
                    full_best_recall.get("playbook_id", "") not in retained
                ),
                "lost_unique_attack_technique_count": len(lost),
                "lost_unique_attack_techniques": ";".join(sorted(lost)),
                "unreduced_generated_achievable_recall": (
                    f"{first_metric(full_gen, 'achievable_combined_attack_recall'):.12f}"
                ),
                "reduced_generated_achievable_recall": (
                    f"{first_metric(reduced_gen, 'achievable_combined_attack_recall'):.12f}"
                ),
                "unreduced_augmented_achievable_recall": (
                    f"{full_achievable:.12f}"
                ),
                "reduced_augmented_achievable_recall": (
                    f"{reduced_achievable:.12f}"
                ),
                "delta_augmented_achievable_recall_reduced_minus_unreduced": (
                    f"{reduced_achievable - full_achievable:.12f}"
                ),
                "unreduced_augmented_selected_id": selected_full_id,
                "unreduced_augmented_selected_source": full_selected.get(
                    "candidate_source", ""
                ),
                "unreduced_augmented_selected_score": full_selected.get(
                    "total_score", ""
                ),
                "unreduced_augmented_selected_combined_recall": full_selected.get(
                    "combined_attack_recall", ""
                ),
                "reduced_augmented_selected_id": selected_reduced_id,
                "reduced_augmented_selected_source": reduced_selected.get(
                    "candidate_source", ""
                ),
                "reduced_augmented_selected_score": reduced_selected.get(
                    "total_score", ""
                ),
                "reduced_augmented_selected_combined_recall": reduced_selected.get(
                    "combined_attack_recall", ""
                ),
                "selected_playbook_changed": str(
                    selected_full_id != selected_reduced_id
                ),
                "selected_source_changed": str(
                    full_selected.get("candidate_source", "")
                    != reduced_selected.get("candidate_source", "")
                ),
                "delta_selected_combined_recall_reduced_minus_unreduced": (
                    f"{reduced_selected_recall - full_selected_recall:.12f}"
                ),
                "unreduced_selected_generated_kept": (
                    str(selected_full_id in retained)
                    if full_selected.get("candidate_source") == "generated"
                    else ""
                ),
            }
        )
    return output


def paired_statistics(
    differences: np.ndarray,
    rng: np.random.Generator,
    bootstrap_replicates: int,
) -> dict[str, float]:
    differences = np.asarray(differences, dtype=float)
    observed = float(differences.mean())
    indices = rng.integers(
        0,
        len(differences),
        size=(bootstrap_replicates, len(differences)),
    )
    bootstrap = differences[indices].mean(axis=1)
    signs = np.asarray(
        list(itertools.product((-1.0, 1.0), repeat=len(differences))),
        dtype=float,
    )
    null_means = (signs * differences).mean(axis=1)
    p_value = float(
        np.mean(np.abs(null_means) >= abs(observed) - TOLERANCE)
    )
    sd = float(differences.std(ddof=1))
    return {
        "mean": observed,
        "median": float(np.median(differences)),
        "ci_low": float(np.quantile(bootstrap, 0.025)),
        "ci_high": float(np.quantile(bootstrap, 0.975)),
        "exact_permutation_p": p_value,
        "paired_dz": observed / sd if sd > TOLERANCE else 0.0,
    }


def alternative_rows_and_summary(
    primary_root: Path,
    alternative_root: Path,
    *,
    seed: int,
    bootstrap_replicates: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rng = np.random.default_rng(seed)
    detail: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    for strategy in ALTERNATIVES:
        repository_dir = alternative_root / strategy
        evaluation_root = repository_dir / "evaluation"
        reduction_summary = read_json(repository_dir / "reduction_summary.json")
        strategy_rows: list[dict[str, Any]] = []
        for scenario in DEFAULT_SCENARIOS:
            primary_rows = read_csv_dicts(
                candidate_path(primary_root, "augmented-reduced", scenario)
            )
            alternative_rows = read_csv_dicts(
                candidate_path(
                    evaluation_root,
                    "augmented-reduced",
                    scenario,
                )
            )
            primary = stable_best(primary_rows)
            alternative = stable_best(alternative_rows)
            primary_combined = to_float(
                primary.get("combined_attack_recall"), 0.0
            )
            alternative_combined = to_float(
                alternative.get("combined_attack_recall"), 0.0
            )
            primary_achievable = first_metric(
                primary_rows, "achievable_combined_attack_recall"
            )
            alternative_achievable = first_metric(
                alternative_rows, "achievable_combined_attack_recall"
            )
            primary_normalized = (
                primary_combined / primary_achievable
                if primary_achievable > 0
                else 0.0
            )
            alternative_normalized = (
                alternative_combined / alternative_achievable
                if alternative_achievable > 0
                else 0.0
            )
            row = {
                "strategy": strategy,
                "scenario_id": scenario,
                "retained_repository_size": reduction_summary.get(
                    "retained_playbooks", ""
                ),
                "selected_playbook_id": alternative.get("playbook_id", ""),
                "selected_source": alternative.get("candidate_source", ""),
                "combined_recall": f"{alternative_combined:.12f}",
                "achievable_recall": f"{alternative_achievable:.12f}",
                "normalized_recall": f"{alternative_normalized:.12f}",
                "selected_action_count": alternative.get("action_count", ""),
                "primary_selected_playbook_id": primary.get("playbook_id", ""),
                "primary_selected_source": primary.get("candidate_source", ""),
                "selected_source_changed": str(
                    alternative.get("candidate_source", "")
                    != primary.get("candidate_source", "")
                ),
                "selected_playbook_changed": str(
                    alternative.get("playbook_id", "")
                    != primary.get("playbook_id", "")
                ),
                "primary_combined_recall": f"{primary_combined:.12f}",
                "primary_achievable_recall": f"{primary_achievable:.12f}",
                "primary_normalized_recall": f"{primary_normalized:.12f}",
                "primary_action_count": primary.get("action_count", ""),
                "delta_combined_recall": (
                    f"{alternative_combined - primary_combined:.12f}"
                ),
                "delta_achievable_recall": (
                    f"{alternative_achievable - primary_achievable:.12f}"
                ),
                "delta_normalized_recall": (
                    f"{alternative_normalized - primary_normalized:.12f}"
                ),
                "delta_action_count": (
                    f"{to_float(alternative.get('action_count'), 0.0) - to_float(primary.get('action_count'), 0.0):.12f}"
                ),
            }
            detail.append(row)
            strategy_rows.append(row)

        combined_differences = np.asarray(
            [to_float(row["delta_combined_recall"], 0.0) for row in strategy_rows]
        )
        achievable_differences = np.asarray(
            [to_float(row["delta_achievable_recall"], 0.0) for row in strategy_rows]
        )
        normalized_differences = np.asarray(
            [to_float(row["delta_normalized_recall"], 0.0) for row in strategy_rows]
        )
        combined_stats = paired_statistics(
            combined_differences, rng, bootstrap_replicates
        )
        achievable_stats = paired_statistics(
            achievable_differences, rng, bootstrap_replicates
        )
        normalized_stats = paired_statistics(
            normalized_differences, rng, bootstrap_replicates
        )
        sources = [
            row["selected_source"] for row in strategy_rows
        ]
        summary.append(
            {
                "strategy": strategy,
                "retained_repository_size": reduction_summary.get(
                    "retained_playbooks", ""
                ),
                "scenario_count": len(strategy_rows),
                "generated_winner_count": sources.count("generated"),
                "community_winner_count": sources.count("community"),
                "mean_combined_recall": (
                    f"{np.mean([to_float(row['combined_recall'], 0.0) for row in strategy_rows]):.12f}"
                ),
                "mean_achievable_recall": (
                    f"{np.mean([to_float(row['achievable_recall'], 0.0) for row in strategy_rows]):.12f}"
                ),
                "mean_normalized_recall": (
                    f"{np.mean([to_float(row['normalized_recall'], 0.0) for row in strategy_rows]):.12f}"
                ),
                "mean_selected_action_count": (
                    f"{np.mean([to_float(row['selected_action_count'], 0.0) for row in strategy_rows]):.12f}"
                ),
                **{
                    f"combined_delta_{key}": f"{value:.12f}"
                    for key, value in combined_stats.items()
                },
                **{
                    f"achievable_delta_{key}": f"{value:.12f}"
                    for key, value in achievable_stats.items()
                },
                **{
                    f"normalized_delta_{key}": f"{value:.12f}"
                    for key, value in normalized_stats.items()
                },
            }
        )
    return detail, summary



def main() -> None:
    args = parse_args()
    if args.bootstrap_replicates < 1:
        raise ValueError("--bootstrap-replicates must be positive")
    primary_root = repo_path(args.primary_evaluation_dir)
    unreduced_root = repo_path(args.unreduced_evaluation_dir)
    reduction_report = repo_path(args.canonical_reduction_report)
    alternative_root = repo_path(args.alternative_root)
    out_reduction = repo_path(args.out_reduction_effect)
    out_alt_detail = repo_path(args.out_alternative_by_scenario)
    out_alt_summary = repo_path(args.out_alternative_summary)

    reduction_rows = reduction_effect_rows(
        primary_root,
        unreduced_root,
        reduction_report,
    )
    alternative_detail, alternative_summary = alternative_rows_and_summary(
        primary_root,
        alternative_root,
        seed=args.seed,
        bootstrap_replicates=args.bootstrap_replicates,
    )
    write_csv(out_reduction, reduction_rows, list(reduction_rows[0]))
    write_csv(out_alt_detail, alternative_detail, list(alternative_detail[0]))
    write_csv(out_alt_summary, alternative_summary, list(alternative_summary[0]))
    print(f"Wrote reduction effect to {out_reduction}")
    print(f"Wrote alternative detail to {out_alt_detail}")
    print(f"Wrote alternative summary to {out_alt_summary}")


if __name__ == "__main__":
    main()
