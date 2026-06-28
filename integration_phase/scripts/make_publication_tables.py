#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from closed_loop_common import (
    read_csv_dicts,
    repo_path,
    split_playbook_ids,
    to_float,
    write_csv,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate publication-ready CSV and LaTeX tables for closed-loop evaluation."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation"),
    )
    parser.add_argument(
        "--reduction-summary",
        type=Path,
        default=Path("results/generated_repository/reduction_summary.json"),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("results/evaluation/publication_tables"),
    )
    parser.add_argument("--weakest-limit", type=int, default=5)
    return parser.parse_args()


def selection_file(evaluation_dir: Path, mode: str) -> Path:
    return evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv"


def candidate_file(evaluation_dir: Path, mode: str, scenario: str) -> Path:
    return evaluation_dir / mode / "candidate_scores_per_scenario" / f"{scenario}_candidate_scores.csv"


def scenario_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    return [row for row in read_csv_dicts(path) if row.get("Scenario") and row.get("Scenario") != "Average"]


def avg(rows: list[dict[str, str]], field: str) -> float:
    values = [to_float(row.get(field), 0.0) for row in rows if str(row.get(field, "")).strip()]
    return sum(values) / len(values) if values else 0.0


def first_selected(row: dict[str, str]) -> str:
    ids = split_playbook_ids(row.get("Top_MCDM_Playbook", ""))
    return ids[0] if ids else ""


def candidate_metadata(evaluation_dir: Path, mode: str, scenario: str, playbook_id: str) -> dict[str, str]:
    path = candidate_file(evaluation_dir, mode, scenario)
    if not path.exists():
        return {}
    return next((row for row in read_csv_dicts(path) if row.get("playbook_id") == playbook_id), {})


def latex_escape(value: Any) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def write_latex_table(path: Path, caption: str, label: str, rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    alignment = "l" + "r" * (len(columns) - 1)
    lines = [
        r"\begin{table}[tb]",
        r"\centering",
        rf"\caption{{{latex_escape(caption)}}}",
        rf"\label{{{latex_escape(label)}}}",
        rf"\begin{{tabular}}{{{alignment}}}",
        r"\toprule",
        " & ".join(latex_escape(header) for _field, header in columns) + r" \\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(" & ".join(latex_escape(row.get(field, "")) for field, _header in columns) + r" \\")
    lines.extend([r"\bottomrule", r"\end{tabular}", r"\end{table}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    out_dir = repo_path(args.out_dir)
    reduction_summary_path = repo_path(args.reduction_summary)
    reduction_summary = json.loads(reduction_summary_path.read_text(encoding="utf-8")) if reduction_summary_path.exists() else {}

    table_a_rows: list[dict[str, Any]] = []
    table_b_rows: list[dict[str, Any]] = []
    for mode in ["community-only", "augmented-reduced"]:
        rows = scenario_rows(selection_file(evaluation_dir, mode))
        generated_count = sum(1 for row in rows if row.get("candidate_source") == "generated")
        generated_playbooks = 0
        if mode == "augmented-reduced":
            generated_playbooks = int(reduction_summary.get("selected_playbooks", 0))
        table_a_rows.append({
            "mode": mode,
            "avg_combined_attack_recall": f"{avg(rows, 'combined_attack_recall'):.3f}",
            "avg_achievable_recall": f"{avg(rows, 'achievable_combined_attack_recall'):.3f}",
            "avg_normalized_achievable_recall": f"{avg(rows, 'normalized_combined_attack_recall'):.3f}",
            "generated_selected_count": f"{generated_count}/{len(rows)}",
            "generated_playbook_count": generated_playbooks,
        })
        table_b_rows.append({
            "mode": mode,
            "avg_direct_attack_recall": f"{avg(rows, 'direct_attack_recall'):.3f}",
            "avg_inferred_attack_recall": f"{avg(rows, 'inferred_attack_recall'):.3f}",
            "avg_combined_attack_recall": f"{avg(rows, 'combined_attack_recall'):.3f}",
        })

    augmented_rows = scenario_rows(selection_file(evaluation_dir, "augmented-reduced"))
    weakest = sorted(augmented_rows, key=lambda row: to_float(row.get("normalized_combined_attack_recall"), 0.0))[: args.weakest_limit]
    table_c_rows: list[dict[str, Any]] = []
    for row in weakest:
        scenario = row.get("Scenario", "")
        playbook_id = first_selected(row)
        metadata = candidate_metadata(evaluation_dir, "augmented-reduced", scenario, playbook_id)
        table_c_rows.append({
            "scenario": scenario,
            "selected_playbook_id": playbook_id,
            "selected_source": row.get("candidate_source", ""),
            "combined_attack_recall": f"{to_float(row.get('combined_attack_recall'), 0.0):.3f}",
            "achievable_combined_attack_recall": f"{to_float(row.get('achievable_combined_attack_recall'), 0.0):.3f}",
            "normalized_achievable_recall": f"{to_float(row.get('normalized_combined_attack_recall'), 0.0):.3f}",
            "direct_attack_recall": f"{to_float(row.get('direct_attack_recall'), 0.0):.3f}",
            "inferred_attack_recall": f"{to_float(row.get('inferred_attack_recall'), 0.0):.3f}",
            "action_count": metadata.get("action_count", row.get("selected_action_count", "")),
            "risk_reduction": metadata.get("raw_risk_reduction", row.get("selected_risk_reduction", "")),
        })

    write_csv(
        out_dir / "table_a_main_closed_loop_comparison.csv",
        table_a_rows,
        [
            "mode",
            "avg_combined_attack_recall",
            "avg_achievable_recall",
            "avg_normalized_achievable_recall",
            "generated_selected_count",
            "generated_playbook_count",
        ],
    )
    write_csv(
        out_dir / "table_b_direct_vs_inferred.csv",
        table_b_rows,
        [
            "mode",
            "avg_direct_attack_recall",
            "avg_inferred_attack_recall",
            "avg_combined_attack_recall",
        ],
    )
    write_csv(
        out_dir / "table_c_weakest_normalized_recall.csv",
        table_c_rows,
        [
            "scenario",
            "selected_playbook_id",
            "selected_source",
            "combined_attack_recall",
            "achievable_combined_attack_recall",
            "normalized_achievable_recall",
            "direct_attack_recall",
            "inferred_attack_recall",
            "action_count",
            "risk_reduction",
        ],
    )

    write_latex_table(
        out_dir / "table_a_main_closed_loop_comparison.tex",
        "Main closed-loop comparison.",
        "tab:main_closed_loop_comparison",
        table_a_rows,
        [
            ("mode", "Mode"),
            ("avg_combined_attack_recall", "Avg. combined ATT&CK recall"),
            ("avg_achievable_recall", "Avg. achievable recall"),
            ("avg_normalized_achievable_recall", "Avg. normalized achievable recall"),
            ("generated_selected_count", "Generated selected"),
            ("generated_playbook_count", "Generated playbooks"),
        ],
    )
    write_latex_table(
        out_dir / "table_b_direct_vs_inferred.tex",
        "Direct and inferred ATT&CK recall contributions.",
        "tab:direct_vs_inferred",
        table_b_rows,
        [
            ("mode", "Mode"),
            ("avg_direct_attack_recall", "Avg. direct recall"),
            ("avg_inferred_attack_recall", "Avg. inferred recall"),
            ("avg_combined_attack_recall", "Avg. combined recall"),
        ],
    )
    write_latex_table(
        out_dir / "table_c_weakest_normalized_recall.tex",
        "Weakest normalized-recall scenarios in augmented-reduced mode.",
        "tab:weakest_normalized_recall",
        table_c_rows,
        [
            ("scenario", "Scenario"),
            ("selected_playbook_id", "Selected playbook"),
            ("selected_source", "Source"),
            ("combined_attack_recall", "Combined recall"),
            ("achievable_combined_attack_recall", "Achievable recall"),
            ("normalized_achievable_recall", "Normalized recall"),
            ("direct_attack_recall", "Direct recall"),
            ("inferred_attack_recall", "Inferred recall"),
            ("action_count", "Actions"),
            ("risk_reduction", "Risk reduction"),
        ],
    )
    print(f"Wrote publication tables to {out_dir}")


if __name__ == "__main__":
    main()
