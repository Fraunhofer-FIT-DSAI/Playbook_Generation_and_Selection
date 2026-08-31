#!/usr/bin/env python3
"""Build the factual 16-scenario inventory and ATT&CK Jaccard matrix."""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from statistics import fmean, median
from typing import Any

from closed_loop_common import DEFAULT_SCENARIOS, repo_display_path, repo_path, safe_id


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=Path("data/scenario_profiles"),
    )
    parser.add_argument(
        "--out-inventory",
        type=Path,
        default=Path("results/ics_scenario_inventory.csv"),
    )
    parser.add_argument(
        "--out-jaccard",
        type=Path,
        default=Path("results/ics_scenario_jaccard.csv"),
    )
    parser.add_argument(
        "--out-summary",
        type=Path,
        default=Path("results/ics_scenario_summary.json"),
    )
    return parser.parse_args()


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def generated_hosts(case_dir: Path) -> list[str]:
    input_path = case_dir / "input.P"
    if not input_path.exists():
        return []
    text = input_path.read_text(encoding="utf-8", errors="ignore")
    return sorted(
        set(re.findall(r"vulExists\(([^,]+),", text)),
        key=lambda value: (
            int(re.search(r"\d+", value).group())
            if re.search(r"\d+", value)
            else 10**9,
            value,
        ),
    )


def main() -> None:
    args = parse_args()
    profile_dir = repo_path(args.profile_dir)
    inventory_path = repo_path(args.out_inventory)
    jaccard_path = repo_path(args.out_jaccard)
    summary_path = repo_path(args.out_summary)
    generation_root = repo_path("generation_phase/source/mulval-inputs")

    profiles = []
    for scenario_name in DEFAULT_SCENARIOS:
        path = profile_dir / f"{safe_id(scenario_name)}.json"
        if not path.exists():
            raise FileNotFoundError(path)
        profiles.append((path, json.loads(path.read_text(encoding="utf-8"))))

    attack_sets = {
        profile["scenario_id"]: set(profile["selection_input"]["attack_ids"])
        for _, profile in profiles
    }
    all_attacks = set().union(*attack_sets.values())
    pair_rows = []
    pair_values = []
    for left_index, left in enumerate(sorted(attack_sets)):
        for right in sorted(attack_sets)[left_index + 1:]:
            intersection = attack_sets[left] & attack_sets[right]
            union = attack_sets[left] | attack_sets[right]
            score = len(intersection) / len(union) if union else 0.0
            pair_values.append(score)
            pair_rows.append({
                "scenario_a": left,
                "scenario_b": right,
                "intersection_count": len(intersection),
                "union_count": len(union),
                "jaccard": f"{score:.12f}",
                "intersection_techniques": ";".join(sorted(intersection)),
            })

    inventory_rows = []
    for profile_path, profile in profiles:
        steps = profile.get("steps", [])
        tactics = sorted({
            str(step.get("tactic", "")).strip()
            for step in steps
            if str(step.get("tactic", "")).strip()
        })
        cves = sorted({
            str(step.get("top_cve", "")).strip()
            for step in steps
            if str(step.get("top_cve", "")).strip()
        })
        ordered_steps = []
        for index, step in enumerate(steps):
            ordered_steps.append("|".join([
                str(index),
                str(step.get("order", "")),
                str(step.get("tactic", "") or ""),
                str(step.get("technique", "") or ""),
                str(step.get("selected_attack_id", "") or ""),
                str(step.get("top_cve", "") or ""),
            ]))
        case_name = profile.get("generation_input", {}).get(
            "recommended_mulval_case",
            "",
        )
        hosts = generated_hosts(generation_root / case_name) if case_name else []
        attacks = sorted(attack_sets[profile["scenario_id"]])
        pair_scores = [
            (
                other,
                len(set(attacks) & other_attacks)
                / len(set(attacks) | other_attacks)
                if set(attacks) | other_attacks
                else 0.0,
            )
            for other, other_attacks in sorted(attack_sets.items())
            if other != profile["scenario_id"]
        ]
        inventory_rows.append({
            "scenario_id": profile["scenario_id"],
            "scenario_name": profile["scenario_name"],
            "attack_technique_count": len(attacks),
            "attack_techniques": ";".join(attacks),
            "tactic_count": len(tactics),
            "tactics": ";".join(tactics),
            "cve_count": len(cves),
            "cves": ";".join(cves),
            "source_step_count": len(steps),
            "usable_generation_step_count": sum(
                bool(step.get("usable_for_generation"))
                for step in steps
            ),
            "generated_topology_hosts": ";".join(hosts),
            "ordering": ";".join(ordered_steps),
            "ordering_format": (
                "zero_based_profile_index|source_ORDER|tactic|technique|"
                "selected_attack_id|top_cve"
            ),
            "missing_attack_id_steps": sum(
                not str(step.get("selected_attack_id", "")).strip()
                for step in steps
            ),
            "missing_cve_steps": sum(
                not str(step.get("top_cve", "")).strip()
                for step in steps
            ),
            "missing_cvss_score_steps": sum(
                not str(step.get("cvss_score", "")).strip()
                for step in steps
            ),
            "source_scenario_csv": repo_display_path(
                profile["selection_input"]["scenario_csv"]
            ),
            "source_scenario_sparql": repo_display_path(
                profile["selection_input"]["scenario_sparql"]
            ),
            "profile_path": repo_display_path(profile_path),
            "pairwise_jaccard": ";".join(
                f"{other}:{score:.12f}"
                for other, score in pair_scores
            ),
            "benchmark_unique_attack_techniques": len(all_attacks),
            "dataset_scope": (
                "canonical 16-scenario default from 17 checked-in "
                "df_SCENARIO_*.csv files; local scenario Multiple excluded"
            ),
        })

    fields = list(inventory_rows[0].keys())
    write_csv(inventory_path, inventory_rows, fields)
    write_csv(
        jaccard_path,
        pair_rows,
        [
            "scenario_a",
            "scenario_b",
            "intersection_count",
            "union_count",
            "jaccard",
            "intersection_techniques",
        ],
    )
    min_pair = min(pair_rows, key=lambda row: float(row["jaccard"]))
    max_pair = max(pair_rows, key=lambda row: float(row["jaccard"]))
    summary = {
        "scenario_count": len(profiles),
        "local_scenario_csv_count": 17,
        "excluded_local_scenario": "Multiple",
        "unique_attack_techniques": len(all_attacks),
        "pair_count": len(pair_rows),
        "jaccard_mean": fmean(pair_values),
        "jaccard_median": median(pair_values),
        "jaccard_min": min_pair,
        "jaccard_max": max_pair,
        "identical_attack_sets": [
            row for row in pair_rows if float(row["jaccard"]) == 1.0
        ],
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {inventory_path}")
    print(f"Wrote {jaccard_path}")
    print(f"Wrote {summary_path}")


if __name__ == "__main__":
    main()
