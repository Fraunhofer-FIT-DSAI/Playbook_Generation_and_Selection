#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any

from closed_loop_common import DEFAULT_SCENARIOS, repo_path, safe_id, technique_ids_from_sparql, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build shared scenario profiles from bachelor scenario inputs."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path("selection_phase/source"),
        help="Bachelor selection source inside this repository.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/scenario_profiles"),
        help="Output directory for scenario profile JSON files.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        help="Scenario name to export. May be passed multiple times. Defaults to all canonical scenarios.",
    )
    return parser.parse_args()


def scenario_csv_path(project_root: Path, scenario_name: str) -> Path:
    return (
        project_root
        / "Use-Case"
        / "SparqlQueryGeneration"
        / "LIAO-NO ICS main SCENARIO"
        / f"df_SCENARIO_{scenario_name}.csv"
    )


def scenario_sparql_path(project_root: Path, scenario_name: str) -> Path:
    return (
        project_root
        / "Use-Case"
        / "SparqlQueryGeneration"
        / "SPARQL_QUERIES"
        / f"df_SCENARIO_{scenario_name}.sparql"
    )


def load_stix_name_map(project_root: Path) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for relative in [
        "Attack-CVE-Mapping/enterprise-attack.json",
        "Attack-CVE-Mapping/ics-attack.json",
    ]:
        path = project_root / relative
        data = json.loads(path.read_text(encoding="utf-8"))
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern" or obj.get("revoked"):
                continue
            name = str(obj.get("name", "")).strip().lower()
            external_ids = {
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            }
            if name and external_ids:
                mapping.setdefault(name, set()).update(external_ids)
    return mapping


def load_cvss_rows(project_root: Path) -> dict[tuple[str, str, str], dict[str, str]]:
    path = project_root / "Attack-CVE-Mapping" / "merged_attack_capec_mapping_with_cvss.csv"
    result: dict[tuple[str, str, str], dict[str, str]] = {}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            key = (
                str(row.get("scenario", "")).strip(),
                str(row.get("order", "")).strip(),
                str(row.get("technique", "")).strip().lower(),
            )
            result[key] = row
    return result


def read_scenario_steps(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def selected_attack_ids(
    technique: str,
    scenario_attack_ids: set[str],
    name_map: dict[str, set[str]],
) -> list[str]:
    mapped = name_map.get(technique.strip().lower(), set())
    intersection = sorted(mapped & scenario_attack_ids)
    if intersection:
        return intersection
    return sorted(mapped)


def build_profile(project_root: Path, scenario_name: str) -> dict[str, Any]:
    csv_path = scenario_csv_path(project_root, scenario_name)
    sparql_path = scenario_sparql_path(project_root, scenario_name)
    if not csv_path.exists():
        raise FileNotFoundError(csv_path)
    if not sparql_path.exists():
        raise FileNotFoundError(sparql_path)

    name_map = load_stix_name_map(project_root)
    cvss_rows = load_cvss_rows(project_root)
    scenario_attack_ids = technique_ids_from_sparql(sparql_path)
    scenario_filename = csv_path.name

    steps = []
    for row in read_scenario_steps(csv_path):
        order = str(row.get("ORDER", "")).strip()
        tactic = str(row.get("TACTIC", "")).strip()
        technique = str(row.get("TECHNIQUE", "")).strip()
        attack_ids = selected_attack_ids(technique, scenario_attack_ids, name_map)
        selected_attack_id = attack_ids[0] if attack_ids else ""
        cvss_row = cvss_rows.get((scenario_filename, order, technique.lower()), {})
        top_cve = str(cvss_row.get("top_cve", "")).strip()
        cvss_score = str(cvss_row.get("cvss_score", "")).strip()

        steps.append({
            "order": int(order) if order.isdigit() else order,
            "tactic": tactic,
            "technique": technique,
            "attack_ids": attack_ids,
            "selected_attack_id": selected_attack_id,
            "top_cve": top_cve,
            "cvss_score": cvss_score,
            "cvss_severity": str(cvss_row.get("cvss_severity", "")).strip(),
            "generation_mitre_technique": f"{technique} - {selected_attack_id}" if selected_attack_id else technique,
            "generation_mitre_techniques": [
                f"{technique} - {attack_id}" for attack_id in attack_ids
            ],
            "usable_for_generation": bool(selected_attack_id and top_cve),
        })

    usable_steps = [step for step in steps if step["usable_for_generation"]]
    return {
        "schema_version": "1.0",
        "scenario_name": scenario_name,
        "scenario_id": safe_id(scenario_name),
        "selection_input": {
            "scenario_csv": str(csv_path),
            "scenario_sparql": str(sparql_path),
            "attack_ids": sorted(scenario_attack_ids),
        },
        "generation_input": {
            "recommended_mulval_case": "scenario_" + safe_id(scenario_name),
            "usable_step_count": len(usable_steps),
            "total_step_count": len(steps),
        },
        "steps": steps,
    }


def main() -> None:
    args = parse_args()
    project_root = repo_path(args.project_root)
    out_dir = repo_path(args.out_dir)
    scenarios = args.scenario or DEFAULT_SCENARIOS

    index = {"profiles": []}
    for scenario in scenarios:
        profile = build_profile(project_root, scenario)
        profile_path = out_dir / f"{profile['scenario_id']}.json"
        write_json(profile_path, profile)
        index["profiles"].append({
            "scenario_name": scenario,
            "scenario_id": profile["scenario_id"],
            "path": str(profile_path),
            "attack_count": len(profile["selection_input"]["attack_ids"]),
            "usable_step_count": profile["generation_input"]["usable_step_count"],
        })

    write_json(out_dir / "index.json", index)
    print(f"Wrote {len(index['profiles'])} scenario profiles to {out_dir}")


if __name__ == "__main__":
    main()
