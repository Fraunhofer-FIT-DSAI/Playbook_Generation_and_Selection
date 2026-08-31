#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
from pathlib import Path
from typing import Any

from closed_loop_common import repo_display_path, repo_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize generated playbook outputs across countermeasure top-K values."
    )
    parser.add_argument(
        "--sweep-dir",
        type=Path,
        default=Path("results/generated_repository/k_sweep"),
        help="Directory containing k_XX/export/generated_playbooks.jsonl outputs.",
    )
    parser.add_argument(
        "--k",
        type=int,
        nargs="+",
        default=list(range(0, 11)),
        help="K values to summarize.",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("results/generated_repository/k_sweep/k_sensitivity_summary.csv"),
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("results/generated_repository/k_sweep/k_sensitivity_summary.json"),
    )
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def attack_id_from_incident_item(item: dict[str, Any]) -> str:
    mitre = str(item.get("mitre", ""))
    if "-" in mitre:
        return mitre.rsplit("-", 1)[1].strip().split()[0]
    if "T" in mitre:
        return mitre.strip().split()[-1]
    return ""


def average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def pct(value: float, denominator: float) -> float:
    return value / denominator if denominator else 0.0


def summarize_playbooks(k: int, playbooks: list[dict[str, Any]], summary: dict[str, Any]) -> dict[str, Any]:
    action_counts: list[float] = []
    covered_counts: list[float] = []
    incident_counts: list[float] = []
    direct_recalls: list[float] = []
    risk_before: list[float] = []
    risk_after: list[float] = []
    risk_reductions: list[float] = []
    risk_reduction_pct: list[float] = []
    phase_completeness: list[float] = []
    d3fend_counts: list[float] = []
    artifact_counts: list[float] = []
    total_steps = 0
    family_fallback_steps = 0

    for playbook in playbooks:
        steps = playbook.get("steps", [])
        incident = playbook.get("incident", [])
        covered = {
            str(step.get("attack_technique_id", "")).strip()
            for step in steps
            if str(step.get("attack_technique_id", "")).strip()
        }
        incident_attacks = {
            attack_id_from_incident_item(item)
            for item in incident
            if attack_id_from_incident_item(item)
        }
        before = float(playbook.get("initial_risk") or playbook.get("risk_before") or 0.0)
        after = float(playbook.get("final_risk") or playbook.get("risk_after") or 0.0)
        phases = {
            str(step.get("phase", "")).strip()
            for step in steps
            if str(step.get("phase", "")).strip()
        }
        d3fend = {
            str(step.get("defensive_technique_id", "")).strip()
            for step in steps
            if str(step.get("defensive_technique_id", "")).strip()
        }
        artifacts = {
            str(step.get("defense_artifact_id", "")).strip()
            for step in steps
            if str(step.get("defense_artifact_id", "")).strip()
        }
        total_steps += len(steps)
        family_fallback_steps += sum(
            1
            for step in steps
            if str(step.get("matched_attack_technique_id", "")).strip()
            and str(step.get("matched_attack_technique_id", "")).strip()
            != str(step.get("attack_technique_id", "")).strip()
        )

        action_counts.append(float(len(steps)))
        covered_counts.append(float(len(covered)))
        incident_counts.append(float(len(incident_attacks)))
        direct_recalls.append(pct(float(len(covered & incident_attacks)), float(len(incident_attacks))))
        risk_before.append(before)
        risk_after.append(after)
        risk_reductions.append(max(before - after, 0.0))
        risk_reduction_pct.append(pct(max(before - after, 0.0), before))
        phase_completeness.append(float(len(phases)) / 4.0 if phases else 0.0)
        d3fend_counts.append(float(len(d3fend)))
        artifact_counts.append(float(len(artifacts)))

    return {
        "k": k,
        "playbooks": int(summary.get("playbooks", len(playbooks))),
        "steps": int(summary.get("steps", int(sum(action_counts)))),
        "skipped_incidents": int(summary.get("skipped_incidents", 0)),
        "mean_actions": average(action_counts),
        "median_actions": median(action_counts),
        "max_actions": int(max(action_counts)) if action_counts else 0,
        "mean_covered_attack_techniques": average(covered_counts),
        "max_covered_attack_techniques": int(max(covered_counts)) if covered_counts else 0,
        "mean_incident_attack_techniques": average(incident_counts),
        "mean_direct_attack_recall": average(direct_recalls),
        "family_fallback_step_share": pct(
            float(family_fallback_steps),
            float(total_steps),
        ),
        "mean_d3fend_techniques": average(d3fend_counts),
        "mean_digital_artifacts": average(artifact_counts),
        "mean_phase_completeness": average(phase_completeness),
        "mean_risk_before": average(risk_before),
        "mean_risk_after": average(risk_after),
        "mean_risk_reduction": average(risk_reductions),
        "mean_risk_reduction_pct": average(risk_reduction_pct),
    }


def add_marginals(rows: list[dict[str, Any]]) -> None:
    previous: dict[str, Any] | None = None
    for row in rows:
        if previous is None:
            row["delta_steps_vs_previous_k"] = 0
            row["delta_mean_actions_vs_previous_k"] = 0.0
            row["delta_mean_recall_vs_previous_k"] = 0.0
            row["delta_mean_risk_reduction_pct_vs_previous_k"] = 0.0
        else:
            row["delta_steps_vs_previous_k"] = row["steps"] - previous["steps"]
            row["delta_mean_actions_vs_previous_k"] = row["mean_actions"] - previous["mean_actions"]
            row["delta_mean_recall_vs_previous_k"] = row["mean_direct_attack_recall"] - previous["mean_direct_attack_recall"]
            row["delta_mean_risk_reduction_pct_vs_previous_k"] = (
                row["mean_risk_reduction_pct"] - previous["mean_risk_reduction_pct"]
            )
        previous = row


def recommendation(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    max_risk_pct = max(float(row["mean_risk_reduction_pct"]) for row in rows)
    max_recall = max(float(row["mean_direct_attack_recall"]) for row in rows)
    candidates = [
        row for row in rows
        if float(row["mean_risk_reduction_pct"]) >= 0.99 * max_risk_pct
        and float(row["mean_direct_attack_recall"]) >= 0.99 * max_recall
    ]
    if candidates:
        recommended = min(candidates, key=lambda row: (row["k"], row["mean_actions"]))
        recommendation_rule = (
            "Smallest K within 99% of the best mean risk-reduction percentage and "
            "99% of the best mean direct ATT&CK recall."
        )
    else:
        recommended = max(
            rows,
            key=lambda row: (row["mean_risk_reduction_pct"], row["mean_direct_attack_recall"], -row["mean_actions"]),
        )
        recommendation_rule = (
            "No K was within 99% of both best risk reduction and best direct ATT&CK recall; "
            "selected the K with best mean risk-reduction percentage, then recall, then fewer actions."
        )
    return {
        "best_k_by_mean_risk_reduction_pct": max(rows, key=lambda row: row["mean_risk_reduction_pct"])["k"],
        "best_k_by_mean_direct_attack_recall": max(rows, key=lambda row: row["mean_direct_attack_recall"])["k"],
        "recommended_k": recommended["k"],
        "recommendation_rule": recommendation_rule,
    }


def main() -> None:
    args = parse_args()
    sweep_dir = repo_path(args.sweep_dir)
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    source_summaries: list[dict[str, Any]] = []

    for k in sorted(set(args.k)):
        export_dir = sweep_dir / f"k_{k:02d}" / "export"
        jsonl_path = export_dir / "generated_playbooks.jsonl"
        summary_path = export_dir / "summary.json"
        if not jsonl_path.exists():
            missing.append(str(jsonl_path))
            continue
        summary = read_json(summary_path)
        rows.append(summarize_playbooks(k, read_jsonl(jsonl_path), summary))
        source_summaries.append({
            "k": k,
            "path": repo_display_path(summary_path),
            "sha256": file_sha256(summary_path) if summary_path.exists() else None,
            "incident_seed": summary.get("incident_seed"),
            "cve_table_sha256": summary.get("cve_table_sha256"),
            "input_attack_graph_sha256": summary.get("input_attack_graph_sha256", {}),
            "generated_playbooks_jsonl_sha256": summary.get("generated_playbooks_jsonl_sha256"),
        })

    add_marginals(rows)

    out_csv = repo_path(args.out_csv)
    out_json = repo_path(args.out_json)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        fieldnames = list(rows[0].keys())
        with out_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    payload = {
        "artifact_status": "corrected fixed-attack-graph, single-incident-seed K sensitivity",
        "rows": rows,
        "missing_outputs": missing,
        "recommendation": recommendation(rows),
        "recommendation_caveat": (
            "The rule has no action-budget penalty. It identifies the smallest K within "
            "99% of both maxima; it is not an operational cost-benefit optimum and does "
            "not alter the workshop paper configuration K=3."
        ),
        "invariants": {
            "playbook_count_constant": len({row["playbooks"] for row in rows}) <= 1,
            "skipped_incident_count_constant": len({row["skipped_incidents"] for row in rows}) <= 1,
            "mean_risk_before_constant": len({row["mean_risk_before"] for row in rows}) <= 1,
            "risk_reduction_monotone_non_decreasing": all(
                right["mean_risk_reduction_pct"] + 1e-12 >= left["mean_risk_reduction_pct"]
                for left, right in zip(rows, rows[1:])
            ),
            "direct_recall_monotone_non_decreasing": all(
                right["mean_direct_attack_recall"] + 1e-12 >= left["mean_direct_attack_recall"]
                for left, right in zip(rows, rows[1:])
            ),
        },
        "source_summaries": source_summaries,
    }
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote K sensitivity summary to {out_csv}")


if __name__ == "__main__":
    main()
