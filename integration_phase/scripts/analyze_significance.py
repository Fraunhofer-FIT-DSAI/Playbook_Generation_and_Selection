#!/usr/bin/env python3
"""Paired statistical analysis of the closed-loop comparison across 16 sectors.

The direct, inferred, combined, achievable, and normalized recall channels are
analysed separately. The inferred channel does not use generated direct
provenance, but it is not independent of the generation knowledge because both
phases use ATT&CK-to-D3FEND associations.

For each metric it computes, over the per-scenario paired differences (treatment - baseline):
  - mean / median diff and win/tie/loss counts;
  - an EXACT sign-flip permutation test (two-sided) on the mean when the number of nonzero
    differences is small enough to enumerate (2^m), else a seeded 100k-sample approximation;
  - an exact two-sided Wilcoxon signed-rank test for the small paired sample;
  - Cohen's d_z (paired) effect size;
  - a seeded percentile bootstrap 95% CI on the mean difference.

Input : results/evaluation/corrected/closed_loop_comparison.csv
Output: results/evaluation/corrected/significance_tests.csv and .json
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

METRICS = ["combined_recall", "direct_recall", "inferred_recall", "normalized_recall", "achievable_recall"]
DEFAULT_PAIRS = [("community-only", "augmented-reduced"), ("community-only", "generated-reduced")]
BOOT = 10000
PERM_EXACT_MAX = 22  # enumerate 2^m sign flips up to this many nonzero diffs
TOL = 1e-12


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_repo(start: Path) -> Path:
    for base in (start, *start.parents):
        if (
            base
            / "results"
            / "evaluation"
            / "corrected"
            / "closed_loop_comparison.csv"
        ).exists():
            return base
    return start


def exact_or_sampled_perm_p(d: np.ndarray) -> tuple[float, str]:
    """Two-sided sign-flip permutation p-value on the sum of paired diffs."""
    nz = d[np.abs(d) > TOL]
    m = len(nz)
    if m == 0:
        return 1.0, "degenerate(all-zero)"
    obs = abs(nz.sum())
    absv = np.abs(nz)
    if m <= PERM_EXACT_MAX:
        signs = np.array(list(itertools.product((1.0, -1.0), repeat=m)))  # (2^m, m)
        sums = np.abs(signs @ absv)
        p = float(np.mean(sums >= obs - 1e-12))
        return p, f"exact(2^{m})"
    rng = np.random.default_rng(0)
    draws = rng.choice((1.0, -1.0), size=(100000, m))
    sums = np.abs(draws @ absv)
    return float(np.mean(sums >= obs - 1e-12)), "sampled(1e5)"


def average_ranks(values: np.ndarray) -> np.ndarray:
    """Return one-based average ranks, including exact-value ties."""
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    start = 0
    while start < len(values):
        end = start + 1
        while end < len(values) and abs(values[order[end]] - values[order[start]]) <= TOL:
            end += 1
        average = ((start + 1) + end) / 2.0
        ranks[order[start:end]] = average
        start = end
    return ranks


def exact_wilcoxon_signed_rank(d: np.ndarray) -> tuple[float | None, float, str]:
    """Exact two-sided Wilcoxon signed-rank test for the small paired sample."""
    nonzero = d[np.abs(d) > TOL]
    if len(nonzero) == 0:
        return None, 1.0, "degenerate(all-zero)"
    ranks = average_ranks(np.abs(nonzero))
    observed_positive = float(ranks[nonzero > 0].sum())
    total_rank = float(ranks.sum())
    observed_statistic = min(observed_positive, total_rank - observed_positive)
    statistics = []
    for signs in itertools.product((False, True), repeat=len(nonzero)):
        positive = float(ranks[np.array(signs, dtype=bool)].sum())
        statistics.append(min(positive, total_rank - positive))
    p_value = sum(value <= observed_statistic + TOL for value in statistics) / len(statistics)
    return observed_statistic, p_value, f"internal-exact(2^{len(nonzero)})"


def paired_stats(
    base: np.ndarray,
    treat: np.ndarray,
    *,
    bootstrap_samples: int = BOOT,
    seed: int = 12345,
) -> dict:
    d = treat - base
    n = len(d)
    out = {
        "n": n,
        "baseline_mean": float(base.mean()),
        "treatment_mean": float(treat.mean()),
        "mean_diff": float(d.mean()),
        "median_diff": float(np.median(d)),
        "wins": int((d > TOL).sum()),
        "ties": int((np.abs(d) <= TOL).sum()),
        "losses": int((d < -TOL).sum()),
    }
    p_perm, perm_mode = exact_or_sampled_perm_p(d)
    out["perm_p_two_sided"] = p_perm
    out["perm_mode"] = perm_mode
    try:
        statistic, p_value, method = exact_wilcoxon_signed_rank(d)
        out["wilcoxon_stat"], out["wilcoxon_p"] = statistic, p_value
        out["wilcoxon_method"] = method
    except Exception as exc:  # noqa: BLE001
        out["wilcoxon_stat"], out["wilcoxon_p"] = None, None
        out["wilcoxon_method"] = "error"
        out["wilcoxon_error"] = str(exc)
    sd = d.std(ddof=1) if n > 1 else 0.0
    out["cohen_dz"] = float(d.mean() / sd) if sd > 0 else None
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(bootstrap_samples, n))
    boot_means = d[idx].mean(axis=1)
    out["ci95_mean_diff"] = [float(np.percentile(boot_means, 2.5)), float(np.percentile(boot_means, 97.5))]
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--comparison", type=Path,
                   default=Path("results/evaluation/corrected/closed_loop_comparison.csv"))
    p.add_argument("--out-csv", type=Path, default=Path("results/evaluation/corrected/significance_tests.csv"))
    p.add_argument("--out-json", type=Path, default=Path("results/evaluation/corrected/significance_tests.json"))
    p.add_argument("--alpha", type=float, default=0.05)
    p.add_argument("--bootstrap-samples", type=int, default=BOOT)
    p.add_argument("--seed", type=int, default=12345)
    p.add_argument("--selftest", action="store_true", help="Run deterministic offline tests and exit.")
    return p.parse_args()


def add_holm_adjustment(rows: list[dict], alpha: float) -> None:
    """Add Holm-Bonferroni adjusted permutation p-values within each mode pair."""
    pairs = {(row["baseline"], row["treatment"]) for row in rows}
    for baseline, treatment in pairs:
        group = [row for row in rows if row["baseline"] == baseline and row["treatment"] == treatment]
        ordered = sorted(group, key=lambda row: row["perm_p_two_sided"])
        running = 0.0
        m = len(ordered)
        for rank, row in enumerate(ordered):
            running = max(running, min(1.0, (m - rank) * row["perm_p_two_sided"]))
            row["perm_p_holm"] = running
            row["significant_perm_holm"] = running < alpha


def selftest() -> int:
    checks: list[tuple[bool, str]] = []

    p_value, mode = exact_or_sampled_perm_p(np.array([1.0, 2.0]))
    checks.append((abs(p_value - 0.5) <= TOL and mode == "exact(2^2)", "exact sign-flip p-value"))

    stats_result = paired_stats(
        np.array([0.0, 0.0]),
        np.array([1.0, 2.0]),
        bootstrap_samples=100,
        seed=7,
    )
    checks.append((stats_result["wins"] == 2 and stats_result["mean_diff"] == 1.5, "paired summary"))

    wilcoxon_stat, wilcoxon_p, wilcoxon_mode = exact_wilcoxon_signed_rank(np.array([1.0, 2.0]))
    checks.append((
        wilcoxon_stat == 0.0 and abs(wilcoxon_p - 0.5) <= TOL and wilcoxon_mode == "internal-exact(2^2)",
        "internal exact Wilcoxon fallback",
    ))

    holm_rows = [
        {"baseline": "b", "treatment": "t", "perm_p_two_sided": value}
        for value in (0.01, 0.02, 0.20)
    ]
    add_holm_adjustment(holm_rows, 0.05)
    adjusted = [row["perm_p_holm"] for row in holm_rows]
    checks.append((np.allclose(adjusted, [0.03, 0.04, 0.20]), "Holm-Bonferroni adjustment"))

    ok = True
    for passed, label in checks:
        print(("PASS" if passed else "FAIL") + f": {label}")
        ok &= passed
    print("\nSELFTEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    args = parse_args()
    if args.selftest:
        return selftest()
    if not 0.0 < args.alpha < 1.0:
        print("ERROR: --alpha must be strictly between 0 and 1.", file=sys.stderr)
        return 2
    if args.bootstrap_samples < 1:
        print("ERROR: --bootstrap-samples must be positive.", file=sys.stderr)
        return 2
    repo = find_repo(Path.cwd())
    comp_path = args.comparison if args.comparison.is_absolute() else repo / args.comparison
    if not comp_path.exists():
        print(f"ERROR: {comp_path} not found.", file=sys.stderr)
        return 2
    df = pd.read_csv(comp_path)
    if "Scenario" not in df.columns:
        print("ERROR: comparison must contain a Scenario column.", file=sys.stderr)
        return 2
    df = df[df["Scenario"].astype(str) != "Average"].copy()
    if df["Scenario"].duplicated().any():
        print("ERROR: comparison must contain one unique row per Scenario.", file=sys.stderr)
        return 2

    rows: list[dict] = []
    detail: dict = {}
    for baseline, treatment in DEFAULT_PAIRS:
        for metric in METRICS:
            bcol, tcol = f"{baseline}_{metric}", f"{treatment}_{metric}"
            if bcol not in df.columns or tcol not in df.columns:
                continue
            sub = df[["Scenario", bcol, tcol]].copy()
            sub[bcol] = pd.to_numeric(sub[bcol], errors="coerce")
            sub[tcol] = pd.to_numeric(sub[tcol], errors="coerce")
            sub = sub.replace([np.inf, -np.inf], np.nan).dropna()
            if len(sub) < 2:
                continue
            base = sub[bcol].to_numpy(float)
            treat = sub[tcol].to_numpy(float)
            st = paired_stats(
                base,
                treat,
                bootstrap_samples=args.bootstrap_samples,
                seed=args.seed,
            )
            st["profile_values"] = [
                {
                    "scenario": scenario,
                    "baseline": float(baseline_value),
                    "treatment": float(treatment_value),
                    "difference": float(treatment_value - baseline_value),
                }
                for scenario, baseline_value, treatment_value in sub[
                    ["Scenario", bcol, tcol]
                ].itertuples(index=False, name=None)
            ]
            st.update({"baseline": baseline, "treatment": treatment, "metric": metric})
            sig_perm = st["perm_p_two_sided"] is not None and st["perm_p_two_sided"] < args.alpha
            st["significant_perm"] = bool(sig_perm)
            rows.append(st)
    add_holm_adjustment(rows, args.alpha)
    for st in rows:
        detail[f"{st['treatment']}_vs_{st['baseline']}::{st['metric']}"] = st

    cols = ["baseline", "treatment", "metric", "n", "baseline_mean", "treatment_mean",
            "mean_diff", "ci95_mean_diff", "median_diff", "wins", "ties", "losses",
            "perm_p_two_sided", "perm_mode", "wilcoxon_p", "wilcoxon_method", "cohen_dz", "significant_perm"]
    cols.extend(["perm_p_holm", "significant_perm_holm"])
    out_df = pd.DataFrame(rows)[cols]
    out_csv = args.out_csv if args.out_csv.is_absolute() else repo / args.out_csv
    out_json = args.out_json if args.out_json.is_absolute() else repo / args.out_json
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_csv, index=False)
    with out_json.open("w", encoding="utf-8") as fh:
        json.dump({
            "artifact_status": (
                "paper evaluation"
                if "corrected" in comp_path.parts
                else "non-canonical evaluation input"
            ),
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "command": "python " + shlex.join(sys.argv),
            "input": str(
                comp_path.relative_to(repo)
                if comp_path.is_relative_to(repo)
                else comp_path
            ),
            "input_sha256": file_sha256(comp_path),
            "profile_count": len(df),
            "alpha": args.alpha,
            "bootstrap_samples": args.bootstrap_samples,
            "seed": args.seed,
            "multiple_testing": "Holm-Bonferroni within each baseline/treatment metric family",
            "results": detail,
        }, fh, indent=2, sort_keys=True)
        fh.write("\n")

    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 30)
    print(f"Paired analysis over {len(df)} scenarios (alpha={args.alpha}).\n")
    for baseline, treatment in DEFAULT_PAIRS:
        print(f"### {treatment}  vs  {baseline}")
        for metric in METRICS:
            key = f"{treatment}_vs_{baseline}::{metric}"
            if key not in detail:
                continue
            s = detail[key]
            ci = s["ci95_mean_diff"]
            star = "  *SIG(Holm)*" if s["significant_perm_holm"] else ""
            dz = f"{s['cohen_dz']:.2f}" if s["cohen_dz"] is not None else "n/a"
            wp = f"{s['wilcoxon_p']:.3g}" if s["wilcoxon_p"] is not None else "n/a"
            print(f"  {metric:18s} {s['baseline_mean']:.3f} -> {s['treatment_mean']:.3f}  "
                  f"diff={s['mean_diff']:+.4f} CI[{ci[0]:+.4f},{ci[1]:+.4f}]  "
                  f"W/T/L={s['wins']}/{s['ties']}/{s['losses']}  "
                  f"perm_p={s['perm_p_two_sided']:.3g} holm={s['perm_p_holm']:.3g} "
                  f"({s['perm_mode']}) wilcoxon_p={wp} dz={dz}{star}")
        print()
    print(f"Wrote {out_csv}\n      {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
