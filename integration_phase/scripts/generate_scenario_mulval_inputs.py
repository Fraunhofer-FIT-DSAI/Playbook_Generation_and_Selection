#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
from pathlib import Path
from typing import Any

from closed_loop_common import repo_path, safe_id, write_csv, write_json


ENRICHED_FIELDS = [
    "CVE",
    "MITRE_Technique",
    "CVSS",
    "cvss_vector",
    "exploitability_score",
    "impact_score",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate scenario-conditioned MulVAL inputs from shared scenario profiles."
    )
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=Path("data/scenario_profiles"),
        help="Directory created by build_scenario_profiles.py.",
    )
    parser.add_argument(
        "--profile",
        action="append",
        help="Profile JSON path or scenario ID. May be passed multiple times. Defaults to all profiles in index.json.",
    )
    parser.add_argument(
        "--generation-source",
        dest="generation_source",
        type=Path,
        default=Path("generation_phase/source"),
        help="Generation-phase source directory inside this repository.",
    )
    parser.add_argument("--host-count", type=int, default=10)
    parser.add_argument("--vulns-per-host", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--out-cve-table",
        type=Path,
        default=Path("data/scenario_profiles/CVE_MITRE_enriched.scenario.csv"),
        help="Scenario-conditioned CVE table for IncidentGenerator.",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def profile_paths(profile_dir: Path, profile_args: list[str] | None) -> list[Path]:
    if profile_args:
        paths = []
        for item in profile_args:
            path = Path(item)
            if not path.exists():
                path = profile_dir / f"{safe_id(item)}.json"
            if not path.exists():
                raise FileNotFoundError(path)
            paths.append(path)
        return paths

    index_path = profile_dir / "index.json"
    if not index_path.exists():
        raise FileNotFoundError(
            f"Missing {index_path}. Run build_scenario_profiles.py first."
        )
    index = load_json(index_path)
    return [Path(item["path"]) for item in index.get("profiles", [])]


def read_existing_enriched(generation_source: Path) -> dict[str, dict[str, str]]:
    path = generation_source / "Incident_generation" / "CVE_MITRE_enriched.csv"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return {row["CVE"]: row for row in csv.DictReader(fh)}


def default_cvss_values(score_text: str) -> dict[str, str]:
    try:
        score = float(score_text)
    except ValueError:
        score = 7.0
    if score >= 9.0:
        return {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "exploitability_score": "3.9",
            "impact_score": "5.9",
        }
    if score >= 7.0:
        return {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "exploitability_score": "2.8",
            "impact_score": "5.9",
        }
    if score >= 4.0:
        return {
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
            "exploitability_score": "1.2",
            "impact_score": "2.5",
        }
    return {
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        "exploitability_score": "0.4",
        "impact_score": "1.4",
    }


def scenario_vulnerabilities(
    profile: dict[str, Any],
    existing_enriched: dict[str, dict[str, str]],
) -> list[dict[str, str]]:
    rows = []
    seen = set()
    for step in profile.get("steps", []):
        if not step.get("usable_for_generation"):
            continue
        cve = str(step.get("top_cve", "")).strip()
        techniques = [
            str(item).strip()
            for item in step.get("generation_mitre_techniques", step.get("legacy_generation_mitre_techniques", []))
            if str(item).strip()
        ]
        if not techniques:
            legacy_technique = str(step.get("generation_mitre_technique", step.get("legacy_generation_mitre_technique", ""))).strip()
            if legacy_technique:
                techniques = [legacy_technique]
        if not cve or not techniques:
            continue
        for technique in techniques:
            if (cve, technique) in seen:
                continue
            seen.add((cve, technique))
            existing = existing_enriched.get(cve, {})
            defaults = default_cvss_values(str(step.get("cvss_score", "")))
            rows.append({
                "CVE": cve,
                "MITRE_Technique": technique,
                "CVSS": str(step.get("cvss_score") or existing.get("CVSS") or "7.0"),
                "cvss_vector": existing.get("cvss_vector") or defaults["cvss_vector"],
                "exploitability_score": existing.get("exploitability_score") or defaults["exploitability_score"],
                "impact_score": existing.get("impact_score") or defaults["impact_score"],
            })
    return rows


def mulval_atom(value: str) -> str:
    return str(value).replace("'", "\\'")


def write_mulval_input(case_dir: Path, vulnerabilities: list[dict[str, str]], host_count: int, vulns_per_host: int, seed: int) -> None:
    rng = random.Random(seed)
    hosts = [f"host{i}" for i in range(1, host_count + 1)]
    if not vulnerabilities:
        raise ValueError("Profile has no usable CVE/ATT&CK steps for generation.")

    assignments: dict[str, list[dict[str, str]]] = {host: [] for host in hosts}
    shuffled = list(vulnerabilities)
    rng.shuffle(shuffled)
    for index, vuln in enumerate(shuffled):
        assignments[hosts[index % len(hosts)]].append(vuln)

    # Ensure every host has enough vulnerabilities by cycling scenario vulnerabilities.
    for host in hosts:
        while len(assignments[host]) < vulns_per_host:
            assignments[host].append(shuffled[len(assignments[host]) % len(shuffled)])

    target_host = next((host for host in reversed(hosts) if assignments[host]), hosts[-1])
    input_path = case_dir / "input.P"
    with input_path.open("w", encoding="utf-8") as fh:
        fh.write("/* Scenario-conditioned network */\n")
        fh.write("attackerLocated(internet).\n")
        fh.write("hacl(internet, host1, _, _).\n")
        for left, right in zip(hosts, hosts[1:]):
            fh.write(f"hacl({left}, {right}, _, _).\n")
            fh.write(f"hacl({right}, {left}, _, _).\n")
            fh.write(f"advances({left}, {right}).\n")
        fh.write("\n/* Scenario-conditioned vulnerabilities */\n")
        for host in hosts:
            for vuln in assignments[host]:
                cve = mulval_atom(vuln["CVE"])
                technique = mulval_atom(vuln["MITRE_Technique"])
                fh.write(f"vulExists({host}, '{cve}', '{technique}').\n")
        fh.write("\n/* Attacker goal */\n")
        fh.write(f"attackGoal(execCode({target_host} ,_,_)).\n")


def main() -> None:
    args = parse_args()
    generation_source = repo_path(args.generation_source)
    profile_dir = repo_path(args.profile_dir)
    existing_enriched = read_existing_enriched(generation_source)
    rules_path = generation_source / "mulval-new-rules.P"
    if not rules_path.exists():
        raise FileNotFoundError(rules_path)

    all_cve_rows = []
    manifest = []
    for index, path in enumerate(profile_paths(profile_dir, args.profile)):
        profile = load_json(path)
        scenario_id = profile["scenario_id"]
        case_name = profile["generation_input"]["recommended_mulval_case"]
        case_dir = generation_source / "mulval-inputs" / case_name
        case_dir.mkdir(parents=True, exist_ok=True)

        vulnerabilities = scenario_vulnerabilities(profile, existing_enriched)
        write_mulval_input(
            case_dir,
            vulnerabilities,
            args.host_count,
            args.vulns_per_host,
            args.seed + index,
        )
        shutil.copy(rules_path, case_dir / "rules.P")
        write_json(case_dir / "scenario_profile.json", profile)
        all_cve_rows.extend(vulnerabilities)
        manifest.append({
            "scenario_name": profile["scenario_name"],
            "scenario_id": scenario_id,
            "mulval_case": case_name,
            "case_dir": str(case_dir),
            "vulnerability_count": len(vulnerabilities),
            "attack_count": len(profile["selection_input"]["attack_ids"]),
        })

    # Deduplicate rows while preserving order.
    deduped = []
    seen = set()
    for row in all_cve_rows:
        key = (row["CVE"], row["MITRE_Technique"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    out_cve_table = repo_path(args.out_cve_table)
    write_csv(out_cve_table, deduped, ENRICHED_FIELDS)
    write_json(profile_dir / "mulval_generation_manifest.json", {"cases": manifest})
    print(f"Wrote {len(manifest)} MulVAL cases under {generation_source / 'mulval-inputs'}")
    print(f"Wrote scenario CVE table to {out_cve_table}")


if __name__ == "__main__":
    main()
