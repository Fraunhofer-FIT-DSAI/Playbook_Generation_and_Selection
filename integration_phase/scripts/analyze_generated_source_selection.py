#!/usr/bin/env python3
"""Explain generated/community source outcomes in the paper evaluation."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    read_csv_dicts,
    repo_display_path,
    repo_path,
    split_multi,
    to_float,
    write_csv,
)
from selection_protocol import CLOSED_LOOP_BALANCED_WEIGHTS, CRITERIA


TOLERANCE = 1e-12
WEIGHT_ORDER = list(CRITERIA)
NOMINAL_WEIGHTS = np.asarray(
    [CLOSED_LOOP_BALANCED_WEIGHTS[name] for name in WEIGHT_ORDER],
    dtype=float,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument(
        "--reduction-effect",
        type=Path,
        default=Path("results/evaluation/corrected/reduction_effect_by_scenario.csv"),
        help="Optional completed reduced-vs-unreduced comparison used for reason code 2.",
    )
    parser.add_argument(
        "--out-diagnostics-csv",
        type=Path,
        default=Path("results/evaluation/corrected/source_selection_diagnostics.csv"),
    )
    parser.add_argument(
        "--out-source-counts",
        type=Path,
        default=Path("results/evaluation/corrected/source_counts_by_profile.csv"),
    )
    parser.add_argument(
        "--out-portfolio",
        type=Path,
        default=Path("results/evaluation/corrected/portfolio_source_composition.csv"),
    )
    parser.add_argument(
        "--out-weight-stability",
        type=Path,
        default=Path("results/evaluation/corrected/source_weight_stability.csv"),
    )
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def candidate_path(evaluation_dir: Path, scenario: str) -> Path:
    return (
        evaluation_dir
        / "augmented-reduced"
        / "candidate_scores_per_scenario"
        / f"{scenario}_candidate_scores.csv"
    )


def score_path(evaluation_dir: Path, scenario: str, suffix: str) -> Path:
    return (
        evaluation_dir
        / "augmented-reduced"
        / "mcdm_scores_per_scenario"
        / f"{scenario}_{suffix}.json"
    )


def stable_best(rows: list[dict[str, str]]) -> dict[str, str] | None:
    if not rows:
        return None
    return min(
        rows,
        key=lambda row: (
            -to_float(row.get("total_score"), 0.0),
            row.get("playbook_id", ""),
        ),
    )


def missing_criteria(row: dict[str, str] | None) -> str:
    if not row:
        return ""
    return ";".join(
        sorted(
            set(split_multi(row.get("missing_context_fields", "")))
            & set(WEIGHT_ORDER)
        )
    )


def contribution_lists(
    winner: dict[str, str],
    loser: dict[str, str],
) -> tuple[str, str]:
    positive: list[str] = []
    negative: list[str] = []
    for criterion in WEIGHT_ORDER:
        delta = CLOSED_LOOP_BALANCED_WEIGHTS[criterion] * (
            to_float(winner.get(criterion), 0.0)
            - to_float(loser.get(criterion), 0.0)
        )
        if delta > TOLERANCE:
            positive.append(f"{criterion}(+{delta:.6f})")
        elif delta < -TOLERANCE:
            negative.append(f"{criterion}({delta:.6f})")
    return ";".join(positive), ";".join(negative)


def ablation_source_map(path: Path) -> dict[tuple[str, str], str]:
    if not path.exists():
        return {}
    return {
        (row.get("ablation_id", ""), row.get("scenario", "")): row.get(
            "selected_source", ""
        )
        for row in read_csv_dicts(path)
        if row.get("status") == "ok"
    }


def reduction_effect_map(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    return {
        row.get("scenario_id", ""): row
        for row in read_csv_dicts(path)
        if row.get("scenario_id")
    }


def raw_dc_source(
    rows: list[dict[str, str]],
    raw_completeness: dict[str, float],
) -> str:
    rescored = []
    for row in rows:
        playbook_id = row.get("playbook_id", "")
        score = to_float(row.get("total_score"), 0.0)
        raw_dc = float(raw_completeness.get(playbook_id, to_float(row.get("DC"), 0.0)))
        score += CLOSED_LOOP_BALANCED_WEIGHTS["DC"] * (
            raw_dc - to_float(row.get("DC"), 0.0)
        )
        rescored.append((score, playbook_id, row.get("candidate_source", "")))
    if not rescored:
        return ""
    return min(rescored, key=lambda item: (-item[0], item[1]))[2]


def classify_community_win(
    *,
    scenario: str,
    community: dict[str, str],
    generated: dict[str, str] | None,
    exact_tie: bool,
    ablations: dict[tuple[str, str], str],
    raw_dc_winner_source: str,
    reduction_effect: dict[str, dict[str, str]],
) -> tuple[int, str]:
    if generated is None:
        return 1, "No eligible generated candidate appears in the corrected candidate table."

    effect = reduction_effect.get(scenario, {})
    if (
        effect.get("unreduced_augmented_selected_source") == "generated"
        and effect.get("reduced_augmented_selected_source") == "community"
        and effect.get("unreduced_selected_generated_kept") == "False"
    ):
        return (
            2,
            "The unreduced augmented winner is generated, was removed by the canonical reduction, and the reduced winner is community.",
        )

    if exact_tie:
        return (
            8,
            "The best source-specific scores are equal and the lexicographically smaller playbook ID wins.",
        )

    if (
        ablations.get(("zero", scenario)) == "generated"
        or ablations.get(("ignore", scenario)) == "generated"
    ):
        return (
            5,
            "The community candidate wins under the primary neutral=0.5 policy, "
            "while a pre-defined zero or ignore-and-renormalize missing-value "
            "policy changes the selected source to generated.",
        )

    if raw_dc_winner_source == "generated":
        return (
            6,
            "Removing only the implemented DC redundancy adjustment changes the winning source to generated.",
        )

    if ablations.get(("without-AC", scenario)) == "generated":
        return (
            7,
            "The pre-defined without-AC ablation changes the winning source to generated.",
        )

    generated_recall = to_float(generated.get("combined_attack_recall"), 0.0)
    community_recall = to_float(community.get("combined_attack_recall"), 0.0)
    if generated_recall < community_recall - TOLERANCE:
        return (
            3,
            "The highest-scoring generated candidate has lower combined recall than the highest-scoring community candidate.",
        )
    if generated_recall > community_recall + TOLERANCE:
        return (
            4,
            "The highest-scoring generated candidate has higher combined recall but a lower balanced MCDM score.",
        )
    return (
        9,
        "The source-specific candidates have equal combined recall, but the community candidate has the higher balanced MCDM score.",
    )


def build_source_diagnostics(
    evaluation_dir: Path,
    reduction_effect_path: Path,
) -> list[dict[str, Any]]:
    ablations = ablation_source_map(
        evaluation_dir / "ablations" / "ablation_by_scenario.csv"
    )
    reduction_effect = reduction_effect_map(reduction_effect_path)
    output: list[dict[str, Any]] = []

    for scenario in DEFAULT_SCENARIOS:
        rows = read_csv_dicts(candidate_path(evaluation_dir, scenario))
        communities = [
            row for row in rows if row.get("candidate_source") == "community"
        ]
        generated_rows = [
            row for row in rows if row.get("candidate_source") == "generated"
        ]
        best_community = stable_best(communities)
        best_generated = stable_best(generated_rows)
        selected = stable_best(rows)
        if best_community is None or selected is None:
            raise RuntimeError(f"Missing required candidates for {scenario}.")
        opposing = (
            best_generated
            if selected.get("candidate_source") == "community"
            else best_community
        )
        if opposing is None:
            opposing = {}

        score_delta = (
            to_float(best_generated.get("total_score"), 0.0)
            - to_float(best_community.get("total_score"), 0.0)
            if best_generated
            else float("nan")
        )
        recall_delta = (
            to_float(best_generated.get("combined_attack_recall"), 0.0)
            - to_float(best_community.get("combined_attack_recall"), 0.0)
            if best_generated
            else float("nan")
        )
        exact_tie = (
            best_generated is not None
            and abs(score_delta) <= TOLERANCE
        )
        tie_break = (
            exact_tie
            and selected.get("playbook_id")
            == min(
                best_community.get("playbook_id", ""),
                best_generated.get("playbook_id", ""),
            )
        )
        winning, losing = contribution_lists(selected, opposing)

        raw_completeness = read_json(
            score_path(evaluation_dir, scenario, "raw_completeness")
        )
        raw_dc_winner = raw_dc_source(rows, raw_completeness)
        reason_code = ""
        reason = ""
        if selected.get("candidate_source") == "community":
            reason_code, reason = classify_community_win(
                scenario=scenario,
                community=best_community,
                generated=best_generated,
                exact_tie=exact_tie,
                ablations=ablations,
                raw_dc_winner_source=raw_dc_winner,
                reduction_effect=reduction_effect,
            )

        output.append(
            {
                "scenario_id": scenario,
                "selected_playbook_id": selected.get("playbook_id", ""),
                "selected_source": selected.get("candidate_source", ""),
                "selected_total_score": selected.get("total_score", ""),
                "selected_combined_recall": selected.get(
                    "combined_attack_recall", ""
                ),
                "selected_direct_recall": selected.get(
                    "direct_attack_recall", ""
                ),
                "selected_inferred_recall": selected.get(
                    "inferred_attack_recall", ""
                ),
                "best_community_id": best_community.get("playbook_id", ""),
                "best_community_score": best_community.get("total_score", ""),
                "best_community_combined_recall": best_community.get(
                    "combined_attack_recall", ""
                ),
                "best_generated_id": (
                    best_generated.get("playbook_id", "")
                    if best_generated
                    else ""
                ),
                "best_generated_score": (
                    best_generated.get("total_score", "")
                    if best_generated
                    else ""
                ),
                "best_generated_combined_recall": (
                    best_generated.get("combined_attack_recall", "")
                    if best_generated
                    else ""
                ),
                "best_generated_direct_recall": (
                    best_generated.get("direct_attack_recall", "")
                    if best_generated
                    else ""
                ),
                "best_generated_inferred_recall": (
                    best_generated.get("inferred_attack_recall", "")
                    if best_generated
                    else ""
                ),
                "score_delta_generated_minus_community": (
                    "" if np.isnan(score_delta) else f"{score_delta:.12f}"
                ),
                "recall_delta_generated_minus_community": (
                    "" if np.isnan(recall_delta) else f"{recall_delta:.12f}"
                ),
                "generated_candidate_count": len(generated_rows),
                "community_candidate_count": len(communities),
                "exact_tie": str(exact_tie),
                "tie_break_applied": str(tie_break),
                "winning_criteria": winning,
                "losing_criteria": losing,
                "missing_generated_criteria": missing_criteria(best_generated),
                "missing_community_criteria": missing_criteria(best_community),
                "primary_reason_code": reason_code,
                "primary_reason": reason,
            }
        )
    return output


def profile_source_counts(evaluation_dir: Path) -> list[dict[str, Any]]:
    profile_path = evaluation_dir / "selection_profiles" / "profile_by_scenario.csv"
    ablation_path = evaluation_dir / "ablations" / "ablation_by_scenario.csv"
    profile_rows = read_csv_dicts(profile_path)
    ablation_rows = read_csv_dicts(ablation_path)
    definitions = [
        ("closed-loop-balanced", "profile", "closed-loop-balanced"),
        ("coverage-primary", "profile", "coverage-primary"),
        ("90%-coverage-constrained", "profile", "coverage-constrained"),
        ("neutral", "ablation", "neutral"),
        ("zero", "ablation", "zero"),
        ("ignore-and-renormalize", "ablation", "ignore"),
        ("without-DC", "ablation", "without-DC"),
        ("without-DAC", "ablation", "without-DAC"),
        ("without-DTC", "ablation", "without-DTC"),
        ("without-TC", "ablation", "without-TC"),
        ("without-RC", "ablation", "without-RC"),
        ("without-CC", "ablation", "without-CC"),
        ("without-AC", "ablation", "without-AC"),
    ]
    output: list[dict[str, Any]] = []
    for label, source_kind, source_id in definitions:
        if source_kind == "profile":
            rows = [
                row for row in profile_rows if row.get("profile") == source_id
            ]
            combined_field = "combined_attack_recall"
            achievable_field = "achievable_combined_attack_recall"
            normalized_field = "normalized_achievable_recall"
        else:
            rows = [
                row
                for row in ablation_rows
                if row.get("ablation_id") == source_id
                and row.get("status") == "ok"
            ]
            combined_field = "combined_attack_recall"
            achievable_field = "achievable_combined_attack_recall"
            normalized_field = "normalized_achievable_recall"
        sources = Counter(row.get("selected_source", "") for row in rows)
        output.append(
            {
                "profile": label,
                "scenario_count": len(rows),
                "generated_selected_count": sources.get("generated", 0),
                "community_selected_count": sources.get("community", 0),
                "generated_selected_fraction": (
                    f"{sources.get('generated', 0) / len(rows):.12f}"
                    if rows
                    else ""
                ),
                "mean_combined_recall": (
                    f"{np.mean([to_float(row.get(combined_field), 0.0) for row in rows]):.12f}"
                    if rows
                    else ""
                ),
                "mean_achievable_recall": (
                    f"{np.mean([to_float(row.get(achievable_field), 0.0) for row in rows]):.12f}"
                    if rows
                    else ""
                ),
                "mean_normalized_recall": (
                    f"{np.mean([to_float(row.get(normalized_field), 0.0) for row in rows]):.12f}"
                    if rows
                    else ""
                ),
                "source_artifact": repo_display_path(
                    profile_path if source_kind == "profile" else ablation_path
                ),
                "source_row_id": source_id,
            }
        )
    return output


def portfolio_composition(evaluation_dir: Path) -> list[dict[str, Any]]:
    portfolio_path = evaluation_dir / "portfolio" / "portfolio_summary.csv"
    rows = read_csv_dicts(portfolio_path)
    output: list[dict[str, Any]] = []
    for row in rows:
        scenario = row.get("scenario", "")
        if scenario not in DEFAULT_SCENARIOS or row.get("status") != "ok":
            continue
        ids = [
            item.strip()
            for item in row.get("selected_playbook_ids", "").split(";")
            if item.strip()
        ]
        sources = [
            item.strip()
            for item in row.get("selected_sources", "").split(";")
            if item.strip()
        ]
        if len(ids) != len(sources):
            raise RuntimeError(
                f"Portfolio ID/source length mismatch for {scenario}: "
                f"{len(ids)} IDs and {len(sources)} sources."
            )
        source_by_id = dict(zip(ids, sources))
        direct = read_json(score_path(evaluation_dir, scenario, "direct_attack_coverage"))
        inferred = read_json(score_path(evaluation_dir, scenario, "inferred_attack_coverage"))

        def coverage(playbook_id: str) -> set[str]:
            return set(direct.get(playbook_id, [])) | set(
                inferred.get(playbook_id, [])
            )

        generated_union: set[str] = set()
        community_union: set[str] = set()
        for playbook_id in ids:
            if source_by_id.get(playbook_id) == "generated":
                generated_union |= coverage(playbook_id)
            elif source_by_id.get(playbook_id) == "community":
                community_union |= coverage(playbook_id)
        unique_generated = generated_union - community_union
        generated_count = sum(
            1 for source in source_by_id.values() if source == "generated"
        )
        community_count = sum(
            1 for source in source_by_id.values() if source == "community"
        )
        output.append(
            {
                "scenario_id": scenario,
                "portfolio_size": len(ids),
                "selected_playbook_ids": ";".join(ids),
                "selected_sources": ";".join(sources),
                "generated_playbook_count": generated_count,
                "community_playbook_count": community_count,
                "generated_playbook_proportion": (
                    f"{generated_count / len(ids):.12f}" if ids else "0.000000000000"
                ),
                "contains_generated_playbook": str(generated_count > 0),
                "generated_unique_attack_count_beyond_community_members": len(
                    unique_generated
                ),
                "generated_unique_attack_techniques": ";".join(
                    sorted(unique_generated)
                ),
                "generated_contributes_unique_attack_coverage": str(
                    bool(unique_generated)
                ),
                "community_comparison_status": (
                    "available"
                    if community_count
                    else "no_community_member_in_portfolio"
                ),
                "portfolio_combined_recall": row.get(
                    "portfolio_combined_attack_recall", ""
                ),
                "portfolio_normalized_recall": row.get(
                    "portfolio_normalized_achievable_recall", ""
                ),
            }
        )

    generated_profiles = sum(
        row["contains_generated_playbook"] == "True" for row in output
    )
    mean_proportion = np.mean(
        [to_float(row["generated_playbook_proportion"], 0.0) for row in output]
    )
    unique_profiles = sum(
        row["generated_contributes_unique_attack_coverage"] == "True"
        for row in output
    )
    output.append(
        {
            "scenario_id": "Average",
            "portfolio_size": "",
            "selected_playbook_ids": "",
            "selected_sources": "",
            "generated_playbook_count": "",
            "community_playbook_count": "",
            "generated_playbook_proportion": f"{mean_proportion:.12f}",
            "contains_generated_playbook": f"{generated_profiles}/{len(output)}",
            "generated_unique_attack_count_beyond_community_members": "",
            "generated_unique_attack_techniques": "",
            "generated_contributes_unique_attack_coverage": (
                f"{unique_profiles}/{len(output)}"
            ),
            "community_comparison_status": "aggregate",
            "portfolio_combined_recall": (
                f"{np.mean([to_float(row['portfolio_combined_recall'], 0.0) for row in output]):.12f}"
            ),
            "portfolio_normalized_recall": (
                f"{np.mean([to_float(row['portfolio_normalized_recall'], 0.0) for row in output]):.12f}"
            ),
        }
    )
    return output


def safe_correlation(left: np.ndarray, right: np.ndarray) -> float:
    if len(left) < 2 or np.std(left) <= TOLERANCE or np.std(right) <= TOLERANCE:
        return float("nan")
    return float(np.corrcoef(left, right)[0, 1])


def weight_stability(evaluation_dir: Path) -> list[dict[str, Any]]:
    draw_path = evaluation_dir / "weight_sensitivity" / "dirichlet_draws.csv"
    draws = pd.read_csv(draw_path)
    weights = draws[WEIGHT_ORDER].to_numpy(dtype=float)
    output: list[dict[str, Any]] = []

    for scenario in DEFAULT_SCENARIOS:
        frame = pd.read_csv(candidate_path(evaluation_dir, scenario), dtype=str).fillna("")
        frame = frame.sort_values("playbook_id", kind="mergesort").reset_index(drop=True)
        criteria = np.column_stack(
            [
                pd.to_numeric(frame[name], errors="coerce")
                .fillna(0.0)
                .to_numpy(float)
                for name in WEIGHT_ORDER
            ]
        )
        all_scores = weights @ criteria.T
        winner_indices = np.argmax(all_scores, axis=1)
        nominal_scores = criteria @ NOMINAL_WEIGHTS
        nominal_index = int(np.argmax(nominal_scores))
        nominal_id = str(frame.iloc[nominal_index]["playbook_id"])
        nominal_source = str(frame.iloc[nominal_index]["candidate_source"])
        winner_sources = (
            frame.iloc[winner_indices]["candidate_source"].astype(str).to_numpy()
        )
        winner_ids = frame.iloc[winner_indices]["playbook_id"].astype(str).to_numpy()
        generated = (winner_sources == "generated").astype(float)
        nominal_matches = (winner_ids == nominal_id).astype(float)
        selected_recall = pd.to_numeric(
            frame.iloc[winner_indices]["combined_attack_recall"],
            errors="coerce",
        ).fillna(0.0).to_numpy(float)

        correlations: dict[str, float] = {}
        mean_deltas: dict[str, float] = {}
        for index, criterion in enumerate(WEIGHT_ORDER):
            correlations[criterion] = safe_correlation(weights[:, index], generated)
            if 0 < generated.sum() < len(generated):
                mean_deltas[criterion] = float(
                    weights[generated == 1, index].mean()
                    - weights[generated == 0, index].mean()
                )
            else:
                mean_deltas[criterion] = float("nan")
        finite = {
            criterion: value
            for criterion, value in correlations.items()
            if np.isfinite(value)
        }
        strongest = (
            max(finite, key=lambda criterion: abs(finite[criterion]))
            if finite
            else "NOT IDENTIFIABLE"
        )
        strongest_value = finite.get(strongest, float("nan"))
        row: dict[str, Any] = {
            "scenario_id": scenario,
            "nominal_playbook_id": nominal_id,
            "nominal_source": nominal_source,
            "probability_generated_selected": f"{generated.mean():.12f}",
            "probability_nominal_winner_remains_selected": (
                f"{nominal_matches.mean():.12f}"
            ),
            "mean_selected_combined_recall": f"{selected_recall.mean():.12f}",
            "selected_combined_recall_q025": (
                f"{np.quantile(selected_recall, 0.025):.12f}"
            ),
            "selected_combined_recall_q975": (
                f"{np.quantile(selected_recall, 0.975):.12f}"
            ),
            "strongest_source_association_criterion": strongest,
            "strongest_source_association_correlation": (
                ""
                if not np.isfinite(strongest_value)
                else f"{strongest_value:.12f}"
            ),
            "association_interpretation": (
                "positive means larger criterion weight is associated with generated selection"
                if finite
                else "winner source is invariant across all draws"
            ),
        }
        for criterion in WEIGHT_ORDER:
            correlation = correlations[criterion]
            mean_delta = mean_deltas[criterion]
            row[f"{criterion}_generated_selection_correlation"] = (
                "" if not np.isfinite(correlation) else f"{correlation:.12f}"
            )
            row[f"{criterion}_mean_weight_delta_generated_minus_community"] = (
                "" if not np.isfinite(mean_delta) else f"{mean_delta:.12f}"
            )
        output.append(row)
    return output



def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    reduction_effect_path = repo_path(args.reduction_effect)
    out_diagnostics_csv = repo_path(args.out_diagnostics_csv)
    out_source_counts = repo_path(args.out_source_counts)
    out_portfolio = repo_path(args.out_portfolio)
    out_weight_stability = repo_path(args.out_weight_stability)

    diagnostics = build_source_diagnostics(
        evaluation_dir,
        reduction_effect_path,
    )
    source_counts = profile_source_counts(evaluation_dir)
    portfolio = portfolio_composition(evaluation_dir)
    weight_rows = weight_stability(evaluation_dir)

    diagnostic_fields = [
        "scenario_id",
        "selected_playbook_id",
        "selected_source",
        "selected_total_score",
        "selected_combined_recall",
        "selected_direct_recall",
        "selected_inferred_recall",
        "best_community_id",
        "best_community_score",
        "best_community_combined_recall",
        "best_generated_id",
        "best_generated_score",
        "best_generated_combined_recall",
        "best_generated_direct_recall",
        "best_generated_inferred_recall",
        "score_delta_generated_minus_community",
        "recall_delta_generated_minus_community",
        "generated_candidate_count",
        "community_candidate_count",
        "exact_tie",
        "tie_break_applied",
        "winning_criteria",
        "losing_criteria",
        "missing_generated_criteria",
        "missing_community_criteria",
        "primary_reason_code",
        "primary_reason",
    ]
    source_count_fields = list(source_counts[0])
    portfolio_fields = list(portfolio[0])
    weight_fields = list(weight_rows[0])
    write_csv(out_diagnostics_csv, diagnostics, diagnostic_fields)
    write_csv(out_source_counts, source_counts, source_count_fields)
    write_csv(out_portfolio, portfolio, portfolio_fields)
    write_csv(out_weight_stability, weight_rows, weight_fields)

    print(f"Wrote source diagnostics to {out_diagnostics_csv}")
    print(f"Wrote profile source counts to {out_source_counts}")
    print(f"Wrote portfolio composition to {out_portfolio}")
    print(f"Wrote source weight stability to {out_weight_stability}")


if __name__ == "__main__":
    main()
