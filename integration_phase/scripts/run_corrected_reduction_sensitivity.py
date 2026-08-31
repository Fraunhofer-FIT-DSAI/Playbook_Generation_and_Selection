#!/usr/bin/env python3
"""Run GraphDB-backed corrected reduction-cap sensitivity end to end."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shlex
import subprocess
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
    write_json,
)
from run_reduction_sensitivity import reduced_ids_by_scenario


DEFAULT_CAPS = (5, 10, 15, 25, 50)
GRAPHDB_INPUTS = (
    Path("selection_phase/source/IncidentResponseSecurityOntology.rdf"),
    Path("selection_phase/source/GraphDB/d3fend.owl"),
    Path("selection_phase/source/GraphDB/playbooks.owl"),
    Path("selection_phase/source/GraphDB/playbook_step_defend_mapping.owl"),
)
PRIMARY_MANIFEST = Path(
    "results/generated_repository/corrected_k03/"
    "reduced_generated_playbooks_manifest.csv"
)
PRIMARY_OWL = Path(
    "results/generated_repository/corrected_k03/reduced_generated_playbooks.owl"
)
FULL_REDUCTION_REPORT = Path(
    "results/generated_repository/corrected_k03/reduction_report.csv"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caps", type=int, nargs="+", default=list(DEFAULT_CAPS))
    parser.add_argument(
        "--endpoint",
        default="http://localhost:7200/repositories/incident-response",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("results/evaluation/corrected/reduction_sensitivity"),
    )
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], root: Path, command_log: list[str]) -> None:
    rendered = shlex.join(command)
    command_log.append(rendered)
    print(f"+ {rendered}", flush=True)
    subprocess.run(command, cwd=root, check=True)


def manifest_ids(path: Path) -> set[str]:
    return {
        row.get("playbook_id", "").strip()
        for row in read_csv_dicts(path)
        if row.get("playbook_id", "").strip()
    }


def kept_report_ids(path: Path) -> set[str]:
    return {
        row.get("playbook_id", "").strip()
        for row in read_csv_dicts(path)
        if row.get("playbook_id", "").strip()
        and row.get("kept", "").strip().lower() == "true"
    }


def flatten_expected_ids(
    report: Path,
    cap: int,
) -> set[str]:
    missing_manifest = report.with_name("__full_manifest_not_present__.csv")
    by_scenario, _source = reduced_ids_by_scenario(
        missing_manifest,
        report,
        "hybrid",
        cap,
    )
    return set().union(*by_scenario.values()) if by_scenario else set()


def selected_rows(path: Path) -> list[dict[str, str]]:
    return [
        row
        for row in read_csv_dicts(path)
        if row.get("Scenario") and row.get("Scenario") != "Average"
    ]


def average(rows: list[dict[str, str]], field: str) -> float:
    values = [
        to_float(row.get(field), None)
        for row in rows
        if str(row.get(field, "")).strip()
    ]
    values = [value for value in values if value is not None]
    return sum(values) / len(values) if values else 0.0


def summarize_cap(
    cap: int,
    cap_root: Path,
    manifest: Path,
    owl: Path,
    primary_ids: set[str],
    rounded_report_replay_ids: set[str],
) -> dict[str, Any]:
    selection_csv = (
        cap_root
        / "evaluation"
        / "augmented-reduced"
        / "scenario_playbook_evaluation_augmented-reduced.csv"
    )
    rows = selected_rows(selection_csv)
    if len(rows) != len(DEFAULT_SCENARIOS):
        raise RuntimeError(
            f"Cap {cap} produced {len(rows)} scenario rows; expected 16."
        )
    manifest_set = manifest_ids(manifest)
    if not manifest_set.issubset(primary_ids):
        raise RuntimeError(
            f"Cap {cap} contains IDs outside the corrected 167-playbook front."
        )
    manifest_rows = read_csv_dicts(manifest)
    per_scenario = Counter(
        row.get("source_scenario_id", "")
        for row in manifest_rows
        if row.get("playbook_id", "")
    )
    # Manifest rows repeat per step, so count unique IDs per scenario.
    per_scenario_unique: dict[str, set[str]] = {}
    for row in manifest_rows:
        scenario = row.get("source_scenario_id", "")
        playbook_id = row.get("playbook_id", "")
        if scenario and playbook_id:
            per_scenario_unique.setdefault(scenario, set()).add(playbook_id)
    if any(len(ids) > cap for ids in per_scenario_unique.values()):
        raise RuntimeError(f"Cap {cap} was exceeded in a scenario.")

    wrong_source = [
        row["Scenario"]
        for row in rows
        if row.get("Top_Playbook_Source") == "generated"
        and row.get("source_scenario_id", "")
        and row.get("source_scenario_id", "").replace("_", " ")
        != row.get("Scenario", "").replace(",", "")
    ]
    # The canonical source restriction is also checked from candidate tables below.
    candidate_wrong_source = 0
    for scenario in DEFAULT_SCENARIOS:
        candidate_path = (
            cap_root
            / "evaluation"
            / "augmented-reduced"
            / "candidate_scores_per_scenario"
            / f"{scenario}_candidate_scores.csv"
        )
        expected_scenario = (
            scenario.replace(",", "")
            .replace(" ", "_")
        )
        for row in read_csv_dicts(candidate_path):
            if (
                row.get("candidate_source") == "generated"
                and row.get("source_scenario_id") != expected_scenario
            ):
                candidate_wrong_source += 1

    source_counts = Counter(row.get("Top_Playbook_Source", "") for row in rows)
    return {
        "cap_per_scenario": cap,
        "status": "pass",
        "retained_generated_playbooks": len(manifest_set),
        "scenario_count": len(rows),
        "selected_generated_count": source_counts.get("generated", 0),
        "selected_community_count": source_counts.get("community", 0),
        "mean_candidate_count": average(rows, "Candidate_Count"),
        "mean_direct_attack_recall": average(rows, "direct_attack_recall"),
        "mean_inferred_attack_recall": average(rows, "inferred_attack_recall"),
        "mean_combined_attack_recall": average(rows, "combined_attack_recall"),
        "mean_achievable_combined_attack_recall": average(
            rows, "achievable_combined_attack_recall"
        ),
        "mean_normalized_combined_attack_recall": average(
            rows, "normalized_combined_attack_recall"
        ),
        "wrong_source_generated_candidates": candidate_wrong_source,
        "selection_source_label_mismatches": len(wrong_source),
        "manifest": repo_display_path(manifest),
        "manifest_sha256": sha256(manifest),
        "owl": repo_display_path(owl),
        "owl_sha256": sha256(owl),
        "selection_csv": repo_display_path(selection_csv),
        "selection_csv_sha256": sha256(selection_csv),
        "pool_relative_criteria_recomputed": True,
        "graphdb_backed": True,
        "rounded_report_replay_missing_ids": len(
            rounded_report_replay_ids - manifest_set
        ),
        "rounded_report_replay_extra_ids": len(
            manifest_set - rounded_report_replay_ids
        ),
    }


def load_command(python: str, owl: Path) -> list[str]:
    return [
        python,
        "integration_phase/scripts/load_graphdb_files.py",
        "--clear",
        *(str(path) for path in GRAPHDB_INPUTS),
        str(owl),
    ]


def main() -> int:
    args = parse_args()
    if any(cap <= 0 for cap in args.caps):
        raise ValueError("All caps must be positive.")
    root = repo_path(".")
    out_dir = repo_path(args.out_dir)
    primary_manifest = repo_path(PRIMARY_MANIFEST)
    primary_owl = repo_path(PRIMARY_OWL)
    full_report = repo_path(FULL_REDUCTION_REPORT)
    assert (
        root is not None
        and out_dir is not None
        and primary_manifest is not None
        and primary_owl is not None
        and full_report is not None
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    python = sys.executable
    command_log: list[str] = []
    rows: list[dict[str, Any]] = []
    failure: dict[str, str] | None = None
    primary_restored = False
    primary_ids = manifest_ids(primary_manifest)
    report_kept_ids = kept_report_ids(full_report)
    if primary_ids != report_kept_ids:
        raise RuntimeError(
            "Corrected manifest IDs do not equal the kept IDs in the full "
            "7,928-row reduction report."
        )

    try:
        for cap in args.caps:
            cap_root = out_dir / f"cap_{cap:02d}"
            repository_dir = cap_root / "repository"
            manifest = repository_dir / "reduced_generated_playbooks_manifest.csv"
            owl = repository_dir / "reduced_generated_playbooks.owl"
            report = repository_dir / "reduction_report.csv"
            summary = repository_dir / "reduction_summary.json"
            rounded_report_replay_ids = flatten_expected_ids(full_report, cap)

            run(
                [
                    python,
                    "integration_phase/scripts/reduce_generated_playbooks.py",
                    "--manifest",
                    str(primary_manifest),
                    "--owl",
                    str(primary_owl),
                    "--strategy",
                    "hybrid",
                    "--per-scenario",
                    str(cap),
                    "--out-manifest",
                    str(manifest),
                    "--out-owl",
                    str(owl),
                    "--report-csv",
                    str(report),
                    "--summary-json",
                    str(summary),
                ],
                root,
                command_log,
            )
            actual_ids = manifest_ids(manifest)
            if not actual_ids.issubset(primary_ids):
                raise RuntimeError(
                    f"Cap {cap} IDs are not a subset of the corrected front."
                )

            run(load_command(python, owl), root, command_log)
            run(
                [
                    python,
                    "integration_phase/scripts/run_mcdm_selection.py",
                    "--endpoint",
                    args.endpoint,
                    "--mode",
                    "augmented-reduced",
                    "--scoring-profile",
                    "closed-loop-balanced",
                    "--reduced-manifest",
                    str(manifest),
                    "--out-dir",
                    str(cap_root / "evaluation"),
                ],
                root,
                command_log,
            )
            rows.append(
                summarize_cap(
                    cap,
                    cap_root,
                    manifest,
                    owl,
                    primary_ids,
                    rounded_report_replay_ids,
                )
            )
    except Exception as exc:
        failure = {
            "type": type(exc).__name__,
            "message": str(exc),
            "last_command": command_log[-1] if command_log else "",
        }
        raise
    finally:
        try:
            run(load_command(python, primary_owl), root, command_log)
            primary_restored = True
        except Exception as restore_exc:
            if failure is None:
                raise
            failure["restore_failure"] = str(restore_exc)

        output_csv = out_dir / "reduction_sensitivity.csv"
        fieldnames = [
            "cap_per_scenario",
            "status",
            "retained_generated_playbooks",
            "scenario_count",
            "selected_generated_count",
            "selected_community_count",
            "mean_candidate_count",
            "mean_direct_attack_recall",
            "mean_inferred_attack_recall",
            "mean_combined_attack_recall",
            "mean_achievable_combined_attack_recall",
            "mean_normalized_combined_attack_recall",
            "wrong_source_generated_candidates",
            "selection_source_label_mismatches",
            "manifest",
            "manifest_sha256",
            "owl",
            "owl_sha256",
            "selection_csv",
            "selection_csv_sha256",
            "pool_relative_criteria_recomputed",
            "graphdb_backed",
            "rounded_report_replay_missing_ids",
            "rounded_report_replay_extra_ids",
        ]
        write_csv(output_csv, rows, fieldnames)
        metadata = {
            "status": "fail" if failure else "pass",
            "result_state": "paper evaluation",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "command": "python " + shlex.join(sys.argv),
            "endpoint": args.endpoint,
            "caps": args.caps,
            "full_generation_population": len(read_csv_dicts(full_report)),
            "full_reduction_report": repo_display_path(full_report),
            "full_reduction_report_sha256": sha256(full_report),
            "primary_manifest": repo_display_path(primary_manifest),
            "primary_manifest_sha256": sha256(primary_manifest),
            "primary_repository_restored": primary_restored,
            "method": (
                "The corrected 167-playbook manifest is first asserted equal to the "
                "kept-ID set in the full 7,928-row reduction report. For each lower "
                "cap, the corrected reducer is then rerun on that full-precision "
                "Pareto/diversity front, a cap-specific manifest/OWL is loaded into "
                "GraphDB, and source-restricted augmented selection is rerun so RC "
                "and AC are normalized within that cap's candidate pool."
            ),
            "rounded_report_replay_note": (
                "The compact report stores risk objectives at six decimals. Its "
                "standalone cap replay is diagnostic only and can choose different "
                "IDs on near-ties; missing/extra counts are reported but are not used "
                "as the exact cap oracle."
            ),
            "commands": command_log,
            "failure": failure,
            "output": repo_display_path(output_csv),
            "output_sha256": sha256(output_csv),
            "rows": rows,
        }
        write_json(out_dir / "reduction_sensitivity_metadata.json", metadata)

    print(f"Wrote corrected reduction sensitivity to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
