#!/usr/bin/env python3
"""Replay selection under deterministic MCDM weight perturbations."""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from closed_loop_common import DEFAULT_SCENARIOS, repo_display_path, repo_path


CRITERIA = ["DC", "DAC", "DTC", "TC", "RC", "CC", "AC"]
NOMINAL_WEIGHTS = np.array([0.25, 0.20, 0.20, 0.10, 0.15, 0.07, 0.03])
GRID_MULTIPLIERS = [0.0, 0.5, 1.0, 1.5, 2.0]
METRICS = [
    "direct_attack_recall",
    "inferred_attack_recall",
    "combined_attack_recall",
    "normalized_combined_attack_recall",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate-dir",
        type=Path,
        default=Path(
            "results/evaluation/corrected/augmented-reduced/"
            "candidate_scores_per_scenario"
        ),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("results/evaluation/corrected/weight_sensitivity"),
    )
    parser.add_argument("--draws", type=int, default=5000)
    parser.add_argument("--concentration", type=float, default=100.0)
    parser.add_argument("--seed", type=int, default=20260714)
    parser.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize(weights: np.ndarray) -> np.ndarray:
    if np.any(weights < 0):
        raise ValueError("Weights must be non-negative")
    total = float(weights.sum())
    if total <= 0:
        raise ValueError("At least one weight must be positive")
    return weights / total


def load_scenarios(candidate_dir: Path) -> dict[str, dict[str, Any]]:
    scenarios: dict[str, dict[str, Any]] = {}
    for scenario in DEFAULT_SCENARIOS:
        path = candidate_dir / f"{scenario}_candidate_scores.csv"
        if not path.exists():
            raise FileNotFoundError(f"Missing candidate table: {path}")
        frame = pd.read_csv(path, dtype=str).fillna("")
        frame = frame[frame["playbook_id"].astype(str).str.len() > 0].copy()
        frame = frame.sort_values("playbook_id", kind="mergesort").reset_index(drop=True)
        criteria = np.column_stack([
            pd.to_numeric(frame[name], errors="coerce").fillna(0.0).to_numpy(float)
            for name in CRITERIA
        ])
        metrics = {
            name: pd.to_numeric(frame[name], errors="coerce").fillna(0.0).to_numpy(float)
            for name in METRICS
        }
        scenarios[scenario] = {
            "path": path,
            "frame": frame,
            "criteria": criteria,
            "metrics": metrics,
        }
    return scenarios


def evaluate(
    scenarios: dict[str, dict[str, Any]],
    weights: np.ndarray,
    nominal_winners: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    weights = normalize(weights)
    winners: dict[str, str] = {}
    values = {metric: [] for metric in METRICS}
    generated = 0
    nominal_matches = 0
    for scenario, data in scenarios.items():
        scores = data["criteria"] @ weights
        index = int(np.argmax(scores))
        frame = data["frame"]
        playbook_id = str(frame.iloc[index]["playbook_id"])
        winners[scenario] = playbook_id
        generated += int(str(frame.iloc[index].get("candidate_source", "")) == "generated")
        if nominal_winners is not None:
            nominal_matches += int(playbook_id == nominal_winners[scenario])
        for metric in METRICS:
            values[metric].append(float(data["metrics"][metric][index]))
    result: dict[str, Any] = {
        **{name: float(weights[i]) for i, name in enumerate(CRITERIA)},
        "generated_winners": generated,
        "community_winners": len(scenarios) - generated,
        **{
            f"mean_{metric}": float(np.mean(metric_values))
            for metric, metric_values in values.items()
        },
    }
    if nominal_winners is not None:
        result["nominal_winner_fraction"] = nominal_matches / len(scenarios)
    return result, winners


def quantiles(values: list[float]) -> dict[str, float]:
    array = np.asarray(values, dtype=float)
    return {
        "mean": float(array.mean()),
        "sd": float(array.std(ddof=1)) if len(array) > 1 else 0.0,
        "q025": float(np.quantile(array, 0.025)),
        "median": float(np.quantile(array, 0.5)),
        "q975": float(np.quantile(array, 0.975)),
        "min": float(array.min()),
        "max": float(array.max()),
    }


def selftest() -> int:
    frame = pd.DataFrame({
        "playbook_id": ["a", "b"],
        "candidate_source": ["community", "generated"],
    })
    scenarios = {
        "test": {
            "frame": frame,
            "criteria": np.array([[1.0, 0, 0, 0, 0, 0, 0], [1.0, 0, 0, 0, 0, 0, 0]]),
            "metrics": {metric: np.array([0.1, 0.9]) for metric in METRICS},
        }
    }
    result, winners = evaluate(scenarios, NOMINAL_WEIGHTS)
    passed = winners["test"] == "a" and result["generated_winners"] == 0
    print(("PASS" if passed else "FAIL") + ": lexicographic top-1 tie policy")
    return 0 if passed else 1


def main() -> int:
    args = parse_args()
    if args.selftest:
        return selftest()
    if args.draws < 1 or args.concentration <= 0:
        raise ValueError("--draws and --concentration must be positive")

    candidate_dir = repo_path(args.candidate_dir)
    out_dir = repo_path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    scenarios = load_scenarios(candidate_dir)

    nominal_result, nominal_winners = evaluate(scenarios, NOMINAL_WEIGHTS)
    grid_rows = []
    for criterion_index, criterion in enumerate(CRITERIA):
        for multiplier in GRID_MULTIPLIERS:
            weights = NOMINAL_WEIGHTS.copy()
            weights[criterion_index] *= multiplier
            result, _ = evaluate(scenarios, weights, nominal_winners)
            result.update({
                "varied_criterion": criterion,
                "multiplier": multiplier,
            })
            grid_rows.append(result)

    rng = np.random.default_rng(args.seed)
    alpha = NOMINAL_WEIGHTS * args.concentration
    random_rows = []
    for draw_index, weights in enumerate(rng.dirichlet(alpha, size=args.draws)):
        result, _ = evaluate(scenarios, weights, nominal_winners)
        result["draw"] = draw_index
        random_rows.append(result)

    grid_path = out_dir / "one_at_a_time.csv"
    random_path = out_dir / "dirichlet_draws.csv"
    pd.DataFrame(grid_rows).to_csv(grid_path, index=False)
    pd.DataFrame(random_rows).to_csv(random_path, index=False)

    summary_fields = [
        "nominal_winner_fraction",
        "generated_winners",
        *[f"mean_{metric}" for metric in METRICS],
    ]
    summary = {
        "artifact_status": (
            "paper evaluation candidate-table replay"
            if "corrected" in candidate_dir.parts
            else "candidate-table replay; validity inherits the input candidate artifacts"
        ),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + shlex.join(sys.argv),
        "method": {
            "nominal_weights": dict(zip(CRITERIA, NOMINAL_WEIGHTS.tolist())),
            "one_at_a_time_multipliers": GRID_MULTIPLIERS,
            "dirichlet_draws": args.draws,
            "dirichlet_concentration": args.concentration,
            "dirichlet_alpha": dict(zip(CRITERIA, alpha.tolist())),
            "seed": args.seed,
            "tie_policy": (
                "highest recomputed weighted score, then lexicographically "
                "smallest stable playbook_id"
            ),
            "scope": (
                "reweights checked-in criterion values; retrieval and pool-relative "
                "criterion normalization are not rerun"
            ),
        },
        "candidate_tables": {
            scenario: {
                "path": repo_display_path(data["path"]),
                "sha256": file_sha256(data["path"]),
                "rows": len(data["frame"]),
            }
            for scenario, data in scenarios.items()
        },
        "nominal": nominal_result,
        "dirichlet_summary": {
            field: quantiles([float(row[field]) for row in random_rows])
            for field in summary_fields
        },
        "outputs": {
            "one_at_a_time": repo_display_path(grid_path),
            "one_at_a_time_sha256": file_sha256(grid_path),
            "dirichlet_draws": repo_display_path(random_path),
            "dirichlet_draws_sha256": file_sha256(random_path),
        },
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote weight-sensitivity results to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
