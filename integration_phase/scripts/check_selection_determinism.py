#!/usr/bin/env python3
"""Compare two corrected selection runs after canonical row sorting."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from closed_loop_common import DEFAULT_SCENARIOS, repo_display_path, repo_path, write_json


MODES = ("community-only", "generated-reduced", "augmented-reduced")
CRITERIA = ("DC", "DAC", "DTC", "TC", "RC", "CC", "AC")
RECALL_FIELDS = (
    "direct_attack_recall",
    "inferred_attack_recall",
    "combined_attack_recall",
    "achievable_combined_attack_recall",
    "normalized_direct_attack_recall",
    "normalized_inferred_attack_recall",
    "normalized_combined_attack_recall",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--left",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument(
        "--right",
        type=Path,
        default=Path("results/evaluation/corrected_repeat"),
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("results/evaluation/corrected/determinism_check.json"),
    )
    parser.add_argument(
        "--mode",
        action="append",
        choices=MODES,
        help="Mode to compare. May be passed multiple times; defaults to all modes.",
    )
    parser.add_argument(
        "--skip-aggregate",
        action="store_true",
        help="Skip closed_loop_comparison.csv when comparing a targeted mode rerun.",
    )
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(
    rows: list[dict[str, str]],
    keys: tuple[str, ...],
    fields: tuple[str, ...] | None = None,
) -> list[dict[str, str]]:
    selected = rows
    if fields is not None:
        selected = [{field: row.get(field, "") for field in fields} for row in rows]
    return sorted(selected, key=lambda row: tuple(row.get(key, "") for key in keys))


def compare_rows(
    left: list[dict[str, str]],
    right: list[dict[str, str]],
    keys: tuple[str, ...],
    fields: tuple[str, ...] | None = None,
) -> tuple[bool, list[dict[str, object]]]:
    canonical_left = canonical(left, keys, fields)
    canonical_right = canonical(right, keys, fields)
    if canonical_left == canonical_right:
        return True, []
    differences: list[dict[str, object]] = []
    for index in range(max(len(canonical_left), len(canonical_right))):
        left_row = canonical_left[index] if index < len(canonical_left) else None
        right_row = canonical_right[index] if index < len(canonical_right) else None
        if left_row != right_row:
            differences.append(
                {"index": index, "left": left_row, "right": right_row}
            )
            if len(differences) == 5:
                break
    return False, differences


def main() -> int:
    args = parse_args()
    left_root = repo_path(args.left)
    right_root = repo_path(args.right)
    out_json = repo_path(args.out_json)
    assert left_root is not None and right_root is not None and out_json is not None

    checks: dict[str, bool] = {}
    details: dict[str, object] = {}
    input_files: list[dict[str, str]] = []

    selected_modes = tuple(args.mode or MODES)
    for mode in selected_modes:
        candidate_left: list[dict[str, str]] = []
        candidate_right: list[dict[str, str]] = []
        for scenario in DEFAULT_SCENARIOS:
            relative = (
                Path(mode)
                / "candidate_scores_per_scenario"
                / f"{scenario}_candidate_scores.csv"
            )
            left_path = left_root / relative
            right_path = right_root / relative
            if not left_path.exists() or not right_path.exists():
                raise FileNotFoundError(
                    f"Missing determinism input for {mode}/{scenario}: "
                    f"{left_path} or {right_path}"
                )
            candidate_left.extend(read_rows(left_path))
            candidate_right.extend(read_rows(right_path))
            input_files.extend(
                [
                    {
                        "path": repo_display_path(left_path),
                        "sha256": sha256(left_path),
                    },
                    {
                        "path": repo_display_path(right_path),
                        "sha256": sha256(right_path),
                    },
                ]
            )

        candidate_keys = ("Scenario", "playbook_id")
        candidate_id_fields = ("Scenario", "playbook_id")
        criteria_fields = ("Scenario", "playbook_id", *CRITERIA)
        total_fields = ("Scenario", "playbook_id", "total_score")
        recall_fields = ("Scenario", "playbook_id", *RECALL_FIELDS)
        for label, fields in (
            ("candidate_ids", candidate_id_fields),
            ("criterion_values", criteria_fields),
            ("total_scores", total_fields),
            ("candidate_recall_metrics", recall_fields),
        ):
            passed, differences = compare_rows(
                candidate_left,
                candidate_right,
                candidate_keys,
                fields,
            )
            check_name = f"{mode}_{label}_identical"
            checks[check_name] = passed
            if differences:
                details[check_name] = differences

        selection_relative = (
            Path(mode) / f"scenario_playbook_evaluation_{mode}.csv"
        )
        selection_left_path = left_root / selection_relative
        selection_right_path = right_root / selection_relative
        selection_left = [
            row
            for row in read_rows(selection_left_path)
            if row.get("Scenario") != "Average"
        ]
        selection_right = [
            row
            for row in read_rows(selection_right_path)
            if row.get("Scenario") != "Average"
        ]
        selected_fields = ("Scenario", "Top_MCDM_Playbook")
        selected_recall_fields = (
            "Scenario",
            "Top_MCDM_Playbook",
            *RECALL_FIELDS,
        )
        passed, differences = compare_rows(
            selection_left,
            selection_right,
            ("Scenario",),
            selected_fields,
        )
        checks[f"{mode}_selected_ids_identical"] = passed
        if differences:
            details[f"{mode}_selected_ids_identical"] = differences
        passed, differences = compare_rows(
            selection_left,
            selection_right,
            ("Scenario",),
            selected_recall_fields,
        )
        checks[f"{mode}_selected_recall_metrics_identical"] = passed
        if differences:
            details[f"{mode}_selected_recall_metrics_identical"] = differences

    if not args.skip_aggregate:
        comparison_left_path = left_root / "closed_loop_comparison.csv"
        comparison_right_path = right_root / "closed_loop_comparison.csv"
        comparison_left = read_rows(comparison_left_path)
        comparison_right = read_rows(comparison_right_path)
        passed, differences = compare_rows(
            comparison_left,
            comparison_right,
            ("Scenario",),
        )
        checks["aggregate_tables_identical"] = passed
        if differences:
            details["aggregate_tables_identical"] = differences

    payload = {
        "status": "pass" if all(checks.values()) else "fail",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + shlex.join(sys.argv),
        "left": repo_display_path(left_root),
        "right": repo_display_path(right_root),
        "modes": list(selected_modes),
        "aggregate_compared": not args.skip_aggregate,
        "canonical_sort_keys": ["Scenario", "playbook_id"],
        "checks": checks,
        "difference_examples": details,
        "input_file_count": len(input_files),
        "input_files": input_files,
    }
    write_json(out_json, payload)
    print(json.dumps(payload, indent=2))
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
