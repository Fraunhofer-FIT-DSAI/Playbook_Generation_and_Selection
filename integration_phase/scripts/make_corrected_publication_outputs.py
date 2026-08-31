#!/usr/bin/env python3
"""Build paper-ready tables and figures from the evaluated result set."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

os.environ.setdefault("MPLCONFIGDIR", "/tmp/playbook-paper-matplotlib")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from closed_loop_common import repo_display_path, repo_path


MODES = ("community-only", "generated-reduced", "augmented-reduced")
MODE_LABELS = {
    "community-only": "Community-only",
    "generated-reduced": "Generated-reduced",
    "augmented-reduced": "Augmented-reduced",
}
MODE_PROFILES = {
    "community-only": "Coverage-only",
    "generated-reduced": "Closed-loop balanced",
    "augmented-reduced": "Closed-loop balanced",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument(
        "--k-summary",
        type=Path,
        default=Path(
            "results/generated_repository/k_sweep/k_sensitivity_summary.csv"
        ),
    )
    parser.add_argument(
        "--reduction-summary",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/reduction_summary.json"
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/"
            "reduced_generated_playbooks_manifest.csv"
        ),
    )
    parser.add_argument(
        "--mapping-owl",
        type=Path,
        default=Path("selection_phase/source/GraphDB/playbook_step_defend_mapping.owl"),
    )
    parser.add_argument(
        "--out-tables",
        type=Path,
        default=Path("results/evaluation/corrected/publication_tables"),
    )
    parser.add_argument(
        "--out-figures",
        type=Path,
        default=Path("results/evaluation/corrected/publication_figures"),
    )
    parser.add_argument(
        "--endpoint",
        default="http://localhost:7200/repositories/incident-response",
    )
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_scenario_rows(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path)
    return frame.loc[frame["Scenario"] != "Average"].copy()


def average(frame: pd.DataFrame, field: str) -> float:
    return float(pd.to_numeric(frame[field], errors="coerce").mean())


def escape_latex(value: Any) -> str:
    text = str(value)
    replacements = (
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("$", r"\$"),
        ("#", r"\#"),
        ("_", r"\_"),
        ("{", r"\{"),
        ("}", r"\}"),
    )
    for source, target in replacements:
        text = text.replace(source, target)
    return text.replace("K<=3", r"$K\leq3$")


def write_latex(
    path: Path,
    frame: pd.DataFrame,
    caption: str,
    label: str,
    metadata_path: Path,
) -> None:
    alignment = "l" + "r" * max(0, len(frame.columns) - 1)
    lines = [
        r"\begin{table}[tb]",
        r"\centering",
        rf"\caption{{{escape_latex(caption)}}}",
        rf"\label{{{label}}}",
        rf"\begin{{tabular}}{{{alignment}}}",
        r"\toprule",
        " & ".join(escape_latex(column) for column in frame.columns) + r" \\",
        r"\midrule",
    ]
    for _, row in frame.iterrows():
        lines.append(
            " & ".join(escape_latex(row[column]) for column in frame.columns)
            + r" \\"
        )
    lines.extend((r"\bottomrule", r"\end{tabular}", r"\end{table}", ""))
    path.write_text("\n".join(lines), encoding="utf-8")


def base_metadata(
    args: argparse.Namespace,
    manifest: Path,
    mapping_owl: Path,
    repository_count: int,
) -> dict[str, Any]:
    return {
        "artifact_status": "paper evaluation",
        "repository_count": repository_count,
        "manifest": repo_display_path(manifest),
        "manifest_sha256": file_sha256(manifest),
        "mapping_owl": repo_display_path(mapping_owl),
        "mapping_sha256": file_sha256(mapping_owl),
        "graphdb_endpoint": args.endpoint,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + shlex.join(sys.argv),
    }


def write_metadata(
    path: Path,
    common: dict[str, Any],
    source_paths: list[Path],
    artifact_path: Path,
    interpretation: str,
) -> None:
    payload = {
        **common,
        "artifact": repo_display_path(artifact_path),
        "artifact_sha256": file_sha256(artifact_path),
        "interpretation": interpretation,
        "sources": [
            {
                "path": repo_display_path(source),
                "sha256": file_sha256(source),
            }
            for source in source_paths
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_table_pair(
    out_dir: Path,
    stem: str,
    frame: pd.DataFrame,
    caption: str,
    label: str,
    common: dict[str, Any],
    sources: list[Path],
    interpretation: str,
) -> list[Path]:
    csv_path = out_dir / f"{stem}.csv"
    tex_path = out_dir / f"{stem}.tex"
    csv_metadata = out_dir / f"{stem}.csv.metadata.json"
    tex_metadata = out_dir / f"{stem}.tex.metadata.json"
    frame.to_csv(csv_path, index=False)
    write_latex(tex_path, frame, caption, label, tex_metadata)
    write_metadata(csv_metadata, common, sources, csv_path, interpretation)
    write_metadata(tex_metadata, common, sources, tex_path, interpretation)
    return [csv_path, tex_path, csv_metadata, tex_metadata]


def save_figure(
    figure: plt.Figure,
    path: Path,
    common: dict[str, Any],
    sources: list[Path],
    interpretation: str,
) -> list[Path]:
    metadata = {
        "Title": path.stem,
        "Description": "Evaluation figure; see adjacent JSON metadata for provenance.",
    }
    figure.savefig(path, dpi=220, bbox_inches="tight", metadata=metadata)
    plt.close(figure)
    sidecar = path.with_suffix(path.suffix + ".metadata.json")
    write_metadata(sidecar, common, sources, path, interpretation)
    return [path, sidecar]


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    k_summary_path = repo_path(args.k_summary)
    reduction_summary_path = repo_path(args.reduction_summary)
    manifest = repo_path(args.manifest)
    mapping_owl = repo_path(args.mapping_owl)
    out_tables = repo_path(args.out_tables)
    out_figures = repo_path(args.out_figures)
    assert (
        evaluation_dir
        and k_summary_path
        and reduction_summary_path
        and manifest
        and mapping_owl
        and out_tables
        and out_figures
    )
    out_tables.mkdir(parents=True, exist_ok=True)
    out_figures.mkdir(parents=True, exist_ok=True)

    reduction = json.loads(reduction_summary_path.read_text(encoding="utf-8"))
    repository_count = int(reduction["selected_playbooks"])
    if repository_count != 167:
        raise ValueError(
            f"Expected repository count 167, found {repository_count}"
        )
    common = base_metadata(args, manifest, mapping_owl, repository_count)
    outputs: list[Path] = []

    k_frame = pd.read_csv(k_summary_path)
    k_table = k_frame[
        [
            "k",
            "playbooks",
            "mean_actions",
            "mean_direct_attack_recall",
            "mean_digital_artifacts",
            "mean_phase_completeness",
            "mean_risk_reduction_pct",
        ]
    ].copy()
    k_table.columns = [
        "K",
        "Playbooks",
        "Mean actions",
        "Direct recall",
        "Mean artifacts",
        "Phase completeness",
        "Model-derived RR",
    ]
    for column in k_table.columns[2:]:
        k_table[column] = k_table[column].map(lambda value: f"{float(value):.3f}")
    outputs += write_table_pair(
        out_tables,
        "corrected_generation_k_sensitivity",
        k_table,
        "Generation sensitivity for countermeasure budget K=0,...,10.",
        "tab:corrected_generation_k_sensitivity",
        common,
        [k_summary_path],
        (
            "Structural and model-derived generation characteristics. Risk reduction "
            "is not an observed operational effect."
        ),
    )

    reduction_rows = []
    for scenario, values in reduction["scenarios"].items():
        reduction_rows.append({
            "Scenario": scenario.replace("_", " "),
            "Generated": values["input_playbooks"],
            "Retained": values["selected_playbooks"],
            "Retained share": f"{values['selected_playbooks'] / values['input_playbooks']:.3f}",
        })
    reduction_rows.append({
        "Scenario": "Total",
        "Generated": reduction["input_playbooks"],
        "Retained": reduction["selected_playbooks"],
        "Retained share": (
            f"{reduction['selected_playbooks'] / reduction['input_playbooks']:.3f}"
        ),
    })
    reduction_table = pd.DataFrame(reduction_rows)
    outputs += write_table_pair(
        out_tables,
        "corrected_k03_reduction",
        reduction_table,
        "K=3 hybrid reduction, applied independently per scenario.",
        "tab:corrected_k03_reduction",
        common,
        [reduction_summary_path, manifest],
        (
            "N=50 is a per-scenario cap after exact-signature diversity and Pareto "
            "filtering; the filters retain 167 playbooks, so the cap is not forced."
        ),
    )

    selection_paths = {
        mode: evaluation_dir
        / mode
        / f"scenario_playbook_evaluation_{mode}.csv"
        for mode in MODES
    }
    selection_frames = {
        mode: read_scenario_rows(path) for mode, path in selection_paths.items()
    }
    comparison_rows = []
    for mode in MODES:
        frame = selection_frames[mode]
        comparison_rows.append({
            "Repository": MODE_LABELS[mode],
            "Scoring profile": MODE_PROFILES[mode],
            "Candidates": f"{average(frame, 'Candidate_Count'):.3f}",
            "Generated winners": int((frame["candidate_source"] == "generated").sum()),
            "Community winners": int((frame["candidate_source"] == "community").sum()),
            "Combined": f"{average(frame, 'combined_attack_recall'):.3f}",
            "Achievable": f"{average(frame, 'achievable_combined_attack_recall'):.3f}",
            "Normalized": f"{average(frame, 'normalized_combined_attack_recall'):.3f}",
        })
    comparison_table = pd.DataFrame(comparison_rows)
    outputs += write_table_pair(
        out_tables,
        "corrected_closed_loop_comparison",
        comparison_table,
        "Source-restricted top-1 comparison over 16 benchmark profiles.",
        "tab:corrected_closed_loop_comparison",
        common,
        list(selection_paths.values()),
        (
            "Bounded mode/profile comparison. Values describe selected and reachable "
            "ATT&CK coverage, not a repository-only causal effect, response correctness, "
            "or operational effectiveness."
        ),
    )

    channel_rows = []
    for mode in MODES:
        frame = selection_frames[mode]
        channel_rows.append({
            "Repository": MODE_LABELS[mode],
            "Scoring profile": MODE_PROFILES[mode],
            "Direct": f"{average(frame, 'direct_attack_recall'):.3f}",
            "Inferred": f"{average(frame, 'inferred_attack_recall'):.3f}",
            "Combined union": f"{average(frame, 'combined_attack_recall'):.3f}",
            "Achievable": f"{average(frame, 'achievable_combined_attack_recall'):.3f}",
            "Normalized": f"{average(frame, 'normalized_combined_attack_recall'):.3f}",
        })
    channel_table = pd.DataFrame(channel_rows)
    outputs += write_table_pair(
        out_tables,
        "corrected_coverage_channels",
        channel_table,
        "Direct-provenance and ontology-mediated ATT&CK coverage.",
        "tab:corrected_coverage_channels",
        common,
        list(selection_paths.values()),
        (
            "Combined is the set union of direct and inferred coverage, not their "
            "arithmetic sum. Inferred links are candidate associations."
        ),
    )

    profile_path = evaluation_dir / "selection_profiles" / "profile_summary.csv"
    portfolio_path = evaluation_dir / "portfolio" / "portfolio_summary.csv"
    profile = pd.read_csv(profile_path)
    portfolio = pd.read_csv(portfolio_path)
    portfolio_average = portfolio.loc[portfolio["scenario"] == "Average"].iloc[0]
    strategy_rows = []
    labels = {
        "closed-loop-balanced": "Closed-loop balanced",
        "coverage-primary": "Coverage primary",
        "coverage-constrained": "90% coverage constrained",
    }
    for _, row in profile.iterrows():
        strategy_rows.append({
            "Selector": labels[row["profile"]],
            "Combined": f"{float(row['avg_combined_attack_recall']):.3f}",
            "Achievable": f"{float(row['avg_achievable_combined_attack_recall']):.3f}",
            "Normalized": f"{float(row['avg_normalized_achievable_recall']):.3f}",
            "Delta combined": f"{float(row['avg_combined_improvement_vs_closed_loop_balanced']):+.3f}",
            "Delta normalized": f"{float(row['normalized_improvement_vs_closed_loop_balanced']):+.3f}",
        })
    strategy_rows.append({
        "Selector": "Greedy portfolio (K<=3)",
        "Combined": f"{float(portfolio_average['portfolio_combined_attack_recall']):.3f}",
        "Achievable": f"{float(portfolio_average['achievable_combined_attack_recall']):.3f}",
        "Normalized": f"{float(portfolio_average['portfolio_normalized_achievable_recall']):.3f}",
        "Delta combined": f"{float(portfolio_average['delta_combined_vs_closed_loop_balanced']):+.3f}",
        "Delta normalized": f"{float(portfolio_average['delta_normalized_vs_closed_loop_balanced']):+.3f}",
    })
    strategy_table = pd.DataFrame(strategy_rows)
    outputs += write_table_pair(
        out_tables,
        "corrected_coverage_aware_and_portfolio",
        strategy_table,
        "Coverage-aware top-1 and greedy portfolio results.",
        "tab:corrected_coverage_aware_portfolio",
        common,
        [profile_path, portfolio_path],
        (
            "Portfolio coverage is computed over at most three deterministic greedy "
            "members and is not evidence of operational actionability."
        ),
    )

    augmented = selection_frames["augmented-reduced"].copy()
    augmented["headroom"] = (
        pd.to_numeric(
            augmented["achievable_combined_attack_recall"], errors="coerce"
        )
        - pd.to_numeric(augmented["combined_attack_recall"], errors="coerce")
    )
    headroom_table = augmented[
        [
            "Scenario",
            "candidate_source",
            "combined_attack_recall",
            "achievable_combined_attack_recall",
            "normalized_combined_attack_recall",
            "headroom",
        ]
    ].sort_values(["headroom", "Scenario"], ascending=[False, True])
    headroom_table.columns = [
        "Scenario",
        "Winner source",
        "Combined",
        "Achievable",
        "Normalized",
        "Absolute headroom",
    ]
    for column in ("Combined", "Achievable", "Normalized", "Absolute headroom"):
        headroom_table[column] = headroom_table[column].map(
            lambda value: f"{float(value):.3f}"
        )
    outputs += write_table_pair(
        out_tables,
        "corrected_scenario_headroom",
        headroom_table,
        "Scenario-level coverage headroom in augmented-reduced mode.",
        "tab:corrected_scenario_headroom",
        common,
        [selection_paths["augmented-reduced"]],
        (
            "Headroom is achievable combined recall minus selected combined recall "
            "within the source-restricted candidate pool."
        ),
    )

    significance_path = evaluation_dir / "significance_tests.csv"
    significance = pd.read_csv(significance_path)
    uncertainty = significance.loc[
        significance["treatment"] == "augmented-reduced",
        [
            "metric",
            "n",
            "baseline_mean",
            "treatment_mean",
            "mean_diff",
            "ci95_mean_diff",
            "median_diff",
            "perm_p_two_sided",
            "perm_p_holm",
            "cohen_dz",
            "significant_perm_holm",
        ],
    ].copy()
    uncertainty.columns = [
        "Metric",
        "N",
        "Community mean",
        "Augmented mean",
        "Mean difference",
        "Bootstrap 95% CI",
        "Median difference",
        "Permutation p",
        "Holm p",
        "Cohen dz",
        "Holm significant",
    ]
    for column in (
        "Community mean",
        "Augmented mean",
        "Mean difference",
        "Median difference",
        "Permutation p",
        "Holm p",
        "Cohen dz",
    ):
        uncertainty[column] = uncertainty[column].map(
            lambda value: f"{float(value):.4f}"
        )
    outputs += write_table_pair(
        out_tables,
        "corrected_uncertainty_summary",
        uncertainty,
        "Paired uncertainty analysis over the 16 bounded benchmark profiles.",
        "tab:corrected_uncertainty_summary",
        common,
        [significance_path],
        (
            "The unit is a benchmark profile. Two profiles have identical ATT&CK "
            "target sets; results are not generalisation estimates."
        ),
    )

    weight_path = evaluation_dir / "weight_sensitivity" / "summary.json"
    weight = json.loads(weight_path.read_text(encoding="utf-8"))
    weight_rows = []
    for metric, values in weight["dirichlet_summary"].items():
        weight_rows.append({
            "Metric": metric.replace("_", " "),
            "Mean": f"{float(values['mean']):.4f}",
            "Median": f"{float(values['median']):.4f}",
            "2.5%": f"{float(values['q025']):.4f}",
            "97.5%": f"{float(values['q975']):.4f}",
            "Min": f"{float(values['min']):.4f}",
            "Max": f"{float(values['max']):.4f}",
        })
    weight_table = pd.DataFrame(weight_rows)
    outputs += write_table_pair(
        out_tables,
        "corrected_weight_sensitivity",
        weight_table,
        "Seeded 5,000-draw Dirichlet weight sensitivity.",
        "tab:corrected_weight_sensitivity",
        common,
        [weight_path, evaluation_dir / "weight_sensitivity" / "dirichlet_draws.csv"],
        (
            "Weights are fixed heuristic parameters. Draws replay corrected candidate "
            "criteria and do not rerun GraphDB retrieval."
        ),
    )

    design_table = pd.DataFrame([
        {
            "Component": "Generation",
            "Inputs": "16 scenario-conditioned MulVAL cases",
            "Variants": "K=0,...,10; seed 1337",
            "Outputs": "7,928 records; structural and model-derived metrics",
        },
        {
            "Component": "Reduction",
            "Inputs": "K=3 generated corpus",
            "Variants": "Hybrid; N in {5,10,15,25,50}",
            "Outputs": "167 primary records; fresh GraphDB-backed sensitivity",
        },
        {
            "Component": "Primary selection",
            "Inputs": "469 community + 167 generated",
            "Variants": "Community, generated, augmented; source-restricted",
            "Outputs": "Direct/inferred/combined/achievable/normalized recall",
        },
        {
            "Component": "Robustness",
            "Inputs": "Augmented candidate tables",
            "Variants": "Profiles, K<=3 portfolio, missing policies, criteria, weights",
            "Outputs": "Paired uncertainty, stability, fairness, determinism",
        },
        {
            "Component": "SBERT diagnostics",
            "Inputs": "Submitted 4,016 top-1 links",
            "Variants": "Descriptive cutoffs 0.0,0.2,0.3,0.4,0.5",
            "Outputs": "Integrity and score distribution; no accuracy claim",
        },
    ])
    design_sources = [
        k_summary_path,
        reduction_summary_path,
        evaluation_dir / "determinism_check.json",
        evaluation_dir / "fairness_checks.json",
        evaluation_dir / "sbert_mapping_diagnostics_metadata.json",
    ]
    outputs += write_table_pair(
        out_tables,
        "corrected_appendix_evaluation_design",
        design_table,
        "Evaluation design and evidentiary scope.",
        "tab:corrected_evaluation_design",
        common,
        design_sources,
        (
            "Technical and construct-level validation only; no expert, cyber-range, "
            "or operational validation."
        ),
    )

    colors = {
        "black": "#1f2933",
        "blue": "#2f6b8a",
        "green": "#3b7a57",
        "red": "#a44a3f",
        "gold": "#b38b2e",
    }
    figure_k_frame = k_frame.loc[k_frame["k"].between(1, 10)].copy()
    figure, axes = plt.subplots(1, 2, figsize=(9.0, 3.6))
    axes[0].plot(
        figure_k_frame["k"],
        figure_k_frame["mean_actions"],
        marker="o",
        color=colors["black"],
    )
    axes[0].set_xlabel("Per-phase countermeasure cap K")
    axes[0].set_ylabel("Mean actions")
    axes[0].set_xticks(range(1, 11))
    axes[0].grid(axis="y", alpha=0.25)
    axes[1].plot(
        figure_k_frame["k"],
        100 * figure_k_frame["mean_direct_attack_recall"],
        marker="o",
        color=colors["blue"],
        label="Direct ATT&CK recall",
    )
    axes[1].plot(
        figure_k_frame["k"],
        100 * figure_k_frame["mean_risk_reduction_pct"],
        marker="s",
        color=colors["red"],
        label="Model-derived relative risk reduction",
    )
    axes[1].set_xlabel("Per-phase countermeasure cap K")
    axes[1].set_ylabel("Mean (%)")
    axes[1].set_xticks(range(1, 11))
    axes[1].grid(axis="y", alpha=0.25)
    axes[1].legend(frameon=False, fontsize=8)
    figure.tight_layout()
    outputs += save_figure(
        figure,
        out_figures / "corrected_generation_k_sensitivity.png",
        common,
        [k_summary_path],
        "Structural coverage and model-derived risk metadata; no operational claim.",
    )

    channel_numeric = pd.DataFrame([
        {
            "Repository": MODE_LABELS[mode],
            "Direct": average(selection_frames[mode], "direct_attack_recall"),
            "Inferred": average(selection_frames[mode], "inferred_attack_recall"),
            "Combined": average(selection_frames[mode], "combined_attack_recall"),
            "Achievable": average(
                selection_frames[mode], "achievable_combined_attack_recall"
            ),
            "Normalized": average(
                selection_frames[mode], "normalized_combined_attack_recall"
            ),
        }
        for mode in MODES
    ]).set_index("Repository")
    figure, axis = plt.subplots(figsize=(8.2, 3.8))
    channel_numeric.plot(
        kind="bar",
        ax=axis,
        color=[
            colors["red"],
            colors["blue"],
            colors["green"],
            colors["gold"],
            colors["black"],
        ],
        width=0.8,
    )
    axis.set_ylabel("Mean recall")
    axis.set_xlabel("")
    axis.set_ylim(0, 1)
    axis.tick_params(axis="x", rotation=0)
    axis.grid(axis="y", alpha=0.25)
    axis.legend(frameon=False, ncol=3, fontsize=8)
    figure.tight_layout()
    outputs += save_figure(
        figure,
        out_figures / "corrected_closed_loop_coverage.png",
        common,
        list(selection_paths.values()),
        "Combined coverage is a union; achievable is the candidate-pool ceiling.",
    )

    strategy_numeric = strategy_table.copy()
    for column in ("Combined", "Normalized"):
        strategy_numeric[column] = pd.to_numeric(strategy_numeric[column])
    figure, axis = plt.subplots(figsize=(8.2, 3.8))
    positions = range(len(strategy_numeric))
    width = 0.36
    axis.bar(
        [position - width / 2 for position in positions],
        strategy_numeric["Combined"],
        width,
        label="Combined",
        color=colors["blue"],
    )
    axis.bar(
        [position + width / 2 for position in positions],
        strategy_numeric["Normalized"],
        width,
        label="Normalized",
        color=colors["green"],
    )
    axis.set_xticks(list(positions))
    axis.set_xticklabels(
        [
            "Closed-loop\nbalanced",
            "Coverage\nprimary",
            "90% coverage\nconstrained",
            "Portfolio\nK<=3",
        ]
    )
    axis.set_ylabel("Mean recall")
    axis.set_ylim(0, 1)
    axis.grid(axis="y", alpha=0.25)
    axis.legend(frameon=False, ncol=2)
    figure.tight_layout()
    outputs += save_figure(
        figure,
        out_figures / "corrected_selection_profiles.png",
        common,
        [profile_path, portfolio_path],
        "Source-restricted augmented candidate tables only.",
    )

    manifest_path = out_tables / "publication_outputs_manifest.json"
    manifest_payload = {
        **common,
        "outputs": [
            {
                "path": repo_display_path(path),
                "sha256": file_sha256(path),
            }
            for path in outputs
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(outputs)} publication artifacts")
    print(f"Wrote {manifest_path}")


if __name__ == "__main__":
    main()
