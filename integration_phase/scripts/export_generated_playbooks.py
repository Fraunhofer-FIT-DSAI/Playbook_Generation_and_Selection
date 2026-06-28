#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import pandas as pd
except ModuleNotFoundError:
    pd = None

from closed_loop_common import join_multi, repo_path, safe_id, write_csv, write_json, write_jsonl


PHASE_ORDER = {
    "Detect": 0,
    "Isolate": 1,
    "Evict": 2,
    "Restore": 3,
}

PHASE_NAMES = {
    "Detect": "Detection",
    "Isolate": "Containment",
    "Evict": "Eradication",
    "Restore": "Recovery",
}

PROVENANCE_PLAYBOOK_FIELDS = [
    "source_case_id",
    "source_scenario_id",
    "scenario_name",
    "attack_path_id",
    "attacker_start",
    "attacker_goal",
    "cves",
    "cvss_scores",
    "cvss_severities",
    "attack_techniques",
    "d3fend_techniques",
    "digital_artifacts",
    "affected_hosts",
    "host_bindings",
    "risk_before",
    "risk_after",
    "risk_reduction",
    "path_length",
    "action_count",
    "lifecycle_phases_present",
    "phase_completeness",
]

PROVENANCE_STEP_FIELDS = [
    "source_case_id",
    "source_scenario_id",
    "attack_path_id",
    "host_binding",
    "cve",
    "cvss_score",
    "cvss_severity",
    "attack_techniques",
    "defensive_technique_id",
    "defense_artifact_id",
    "phase",
    "command",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export attack-graph-generation generated incident playbooks as normalized "
            "JSONL/CSV plus simple CACAO JSON files."
        )
    )
    parser.add_argument(
        "--generation-source",
        dest="generation_source",
        type=Path,
        default=Path("generation_phase/source"),
        help="Path to the generation phase source directory.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=None,
        help=(
            "MulVAL case directory under the generation source's mulval-inputs directory. "
            "May be passed multiple times. Defaults to NewTest."
        ),
    )
    parser.add_argument(
        "--all-cases",
        action="store_true",
        help="Export every directory under generation_phase/source/mulval-inputs.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Maximum incidents exported per case.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/generated_repository/export"),
        help="Output directory.",
    )
    parser.add_argument(
        "--cve-table",
        type=Path,
        default=None,
        help=(
            "Optional scenario-conditioned CVE_MITRE_enriched.csv. "
            "Use the file produced by generate_scenario_mulval_inputs.py."
        ),
    )
    parser.add_argument(
        "--generated-prefix",
        default="ma_",
        help="Prefix for generated playbook IDs.",
    )
    return parser.parse_args()


def require_pandas():
    if pd is None:
        raise RuntimeError("Missing dependency: pandas. Install dependencies with `pip install -r requirements.txt`.")
    return pd


def add_generation_import_paths(generation_source: Path) -> None:
    sys.path.insert(0, str(generation_source))
    sys.path.insert(0, str(generation_source / "Response_generation"))
    sys.path.insert(0, str(generation_source / "Incident_generation"))


def load_d3fend_lookup(generation_source: Path) -> dict[str, dict[str, str]]:
    pandas = require_pandas()
    mapping_path = generation_source / "defense_techniques" / "d3fend-full-mappings.csv"
    if not mapping_path.exists():
        raise FileNotFoundError(f"Missing D3FEND mapping CSV: {mapping_path}")

    df = pandas.read_csv(mapping_path)
    lookup: dict[str, dict[str, str]] = {}
    for _, row in df.iterrows():
        label = str(row.get("def_tech_label", "")).strip()
        if not label or label in lookup:
            continue
        lookup[label] = {
            "defensive_technique_id": uri_local(row.get("def_tech", "")),
            "defense_artifact_id": uri_local(row.get("def_artifact", "")),
            "offensive_artifact_id": uri_local(row.get("off_artifact", "")),
            "defense_relationship_id": uri_local(row.get("def_artifact_rel", "")),
            "offensive_relationship_id": uri_local(row.get("off_artifact_rel", "")),
        }
    return lookup


def uri_local(value: Any) -> str:
    text = "" if pd is not None and pd.isna(value) else str(value).strip()
    if "#" in text:
        return text.rsplit("#", 1)[1]
    return text


def normalize_scalar(value: Any) -> Any:
    if pd is not None and pd.isna(value):
        return ""
    if hasattr(value, "item"):
        return value.item()
    return value


def cvss_severity(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return ""
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    if value > 0:
        return "LOW"
    return ""


def to_imperative(verb: str) -> str:
    verb = str(verb or "handle").strip()
    lower = verb.lower()
    replacements = {
        "analyzes": "analyze",
        "authorizes": "authorize",
        "disables": "disable",
        "enables": "enable",
        "filters": "filter",
        "isolates": "isolate",
        "locks": "lock",
        "monitors": "monitor",
        "quarantines": "quarantine",
        "removes": "remove",
        "restores": "restore",
        "restricts": "restrict",
        "validates": "validate",
    }
    if lower in replacements:
        verb = replacements[lower]
    elif lower.endswith("ies"):
        verb = verb[:-3] + "y"
    elif lower.endswith(("ches", "shes", "xes", "ses")):
        verb = verb[:-2]
    elif lower.endswith("s") and not lower.endswith("ss"):
        verb = verb[:-1]
    return verb[:1].upper() + verb[1:]


def attack_technique_id(value: Any) -> str:
    match = re.search(r"T[0-9]+(?:\.[0-9]+)?", str(value or ""))
    return match.group(0) if match else ""


def load_case_profile(case_dir: Path) -> dict[str, Any]:
    profile_path = case_dir / "scenario_profile.json"
    if not profile_path.exists():
        return {}
    return json.loads(profile_path.read_text(encoding="utf-8"))


def scenario_id_from_case(case: str) -> str:
    return case.removeprefix("scenario_") if str(case).startswith("scenario_") else ""


def parse_mulval_context(case_dir: Path) -> dict[str, str]:
    input_path = case_dir / "input.P"
    context = {"attacker_start": "", "attacker_goal": ""}
    if not input_path.exists():
        return context
    text = input_path.read_text(encoding="utf-8", errors="ignore")
    start_match = re.search(r"attackerLocated\(([^)]+)\)\.", text)
    goal_match = re.search(r"attackGoal\((.*?)\)\.", text)
    if start_match:
        context["attacker_start"] = start_match.group(1).strip()
    if goal_match:
        context["attacker_goal"] = goal_match.group(1).strip()
    return context


def incident_step_lookup(incident: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for item in incident:
        host = str(item.get("host", "")).strip()
        attack_id = attack_technique_id(item.get("mitre", ""))
        if host and attack_id and (host, attack_id) not in lookup:
            lookup[(host, attack_id)] = item
    return lookup


def match_incident_step(
    lookup: dict[tuple[str, str], dict[str, Any]],
    host: str,
    attack_id: str,
) -> dict[str, Any]:
    if (host, attack_id) in lookup:
        return lookup[(host, attack_id)]
    for (known_host, _known_attack), item in lookup.items():
        if known_host == host:
            return item
    return {}


def missing_fields(record: dict[str, Any], fields: list[str]) -> list[str]:
    missing = []
    for field in fields:
        value = record.get(field)
        if value is None or value == "" or value == [] or value == {}:
            missing.append(field)
    return missing


def aggregate_playbook_provenance(playbook: dict[str, Any]) -> None:
    steps = playbook.get("steps", [])
    incident = playbook.get("incident", [])
    cves = {str(item.get("cve", "")).strip() for item in incident if str(item.get("cve", "")).strip()}
    cvss_scores = {str(item.get("cvss", "")).strip() for item in incident if str(item.get("cvss", "")).strip()}
    attack_techniques = {
        attack_technique_id(item.get("mitre", ""))
        for item in incident
        if attack_technique_id(item.get("mitre", ""))
    }
    attack_techniques.update(
        step.get("attack_technique_id", "")
        for step in steps
        if step.get("attack_technique_id", "")
    )
    hosts = {str(item.get("host", "")).strip() for item in incident if str(item.get("host", "")).strip()}
    hosts.update(step.get("host", "") for step in steps if step.get("host", ""))

    host_bindings: dict[str, dict[str, list[str]]] = {}
    for host in hosts:
        host_bindings[host] = {
            "cves": sorted({str(item.get("cve", "")).strip() for item in incident if item.get("host") == host and str(item.get("cve", "")).strip()}),
            "attack_techniques": sorted({attack_technique_id(item.get("mitre", "")) for item in incident if item.get("host") == host and attack_technique_id(item.get("mitre", ""))}),
            "d3fend_techniques": sorted({step.get("defensive_technique_id", "") for step in steps if step.get("host") == host and step.get("defensive_technique_id", "")}),
            "digital_artifacts": sorted({step.get("defense_artifact_id", "") for step in steps if step.get("host") == host and step.get("defense_artifact_id", "")}),
        }

    phases = {step.get("phase", "") for step in steps if step.get("phase", "")}
    phase_labels = {step.get("phase_label", "") for step in steps if step.get("phase_label", "")}
    initial_risk = float(playbook.get("initial_risk", 0.0) or 0.0)
    final_risk = float(playbook.get("final_risk", 0.0) or 0.0)

    playbook.update({
        "source": "generated",
        "source_case_id": playbook.get("source_case", ""),
        "risk_before": initial_risk,
        "risk_after": final_risk,
        "risk_reduction": max(initial_risk - final_risk, 0.0),
        "cves": sorted(cves),
        "cvss_scores": sorted(cvss_scores),
        "cvss_severities": sorted({cvss_severity(score) for score in cvss_scores if cvss_severity(score)}),
        "attack_techniques": sorted(attack_techniques),
        "d3fend_techniques": sorted({step.get("defensive_technique_id", "") for step in steps if step.get("defensive_technique_id", "")}),
        "digital_artifacts": sorted({step.get("defense_artifact_id", "") for step in steps if step.get("defense_artifact_id", "")}),
        "affected_hosts": sorted(hosts),
        "host_bindings": host_bindings,
        "path_length": len(incident),
        "action_count": len(steps),
        "lifecycle_phases_present": sorted(phases),
        "phase_completeness": len(phase_labels & set(PHASE_ORDER)) / len(PHASE_ORDER),
    })
    playbook["missing_provenance_fields"] = missing_fields(playbook, PROVENANCE_PLAYBOOK_FIELDS)


def sort_and_deduplicate_records(records: list[tuple[int, dict[str, Any]]]) -> list[tuple[int, dict[str, Any]]]:
    best_by_key: dict[tuple[str, str, str, str, str], tuple[int, dict[str, Any]]] = {}
    for order, record in records:
        key = (
            str(record.get("def_tactic_label", "")).strip(),
            str(record.get("def_tech_label", "")).strip(),
            str(record.get("def_artifact_label", "")).strip(),
            attack_technique_id(record.get("off_tech_id", "")),
            str(record.get("host", "")).strip(),
        )
        existing = best_by_key.get(key)
        if existing is None:
            best_by_key[key] = (order, record)
            continue
        existing_risk = float(existing[1].get("risk_reduction") or 0.0)
        current_risk = float(record.get("risk_reduction") or 0.0)
        if current_risk > existing_risk:
            best_by_key[key] = (order, record)
    return sorted(best_by_key.values(), key=lambda item: item[0])


def make_command(row: dict[str, Any]) -> str:
    rel = to_imperative(row.get("def_artifact_rel_label", "handle"))
    artifact = row.get("def_artifact_label") or "artifact"
    technique = row.get("def_tech_label") or row.get("defensive_technique_id")
    return f"{rel} {artifact} using the defensive technique {technique}."


def stable_uuid(text: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, text))


def cacao_playbook(playbook: dict[str, Any]) -> dict[str, Any]:
    workflow: dict[str, Any] = {}
    start_id = "start--" + stable_uuid(playbook["playbook_id"] + ":start")
    end_id = "end--" + stable_uuid(playbook["playbook_id"] + ":end")
    workflow_start = start_id

    previous = start_id
    workflow[start_id] = {
        "type": "start",
        "name": "Start " + playbook["playbook_name"],
    }

    for index, step in enumerate(playbook["steps"]):
        action_id = "action--" + stable_uuid(step["step_id"])
        workflow[previous]["on_completion"] = action_id
        workflow[action_id] = {
            "type": "action",
            "name": step["step_name"],
            "description": step["phase"],
            "commands": [
                {
                    "type": "manual",
                    "command": step["command"],
                }
            ],
            "custom_properties": {
                "x_defensive_technique": step["defensive_technique_id"],
                "x_defensive_technique_label": step["defensive_technique_label"],
                "x_attack_technique": step["attack_technique_id"],
                "x_cve": step.get("cve", ""),
                "x_host": step.get("host_binding", ""),
                "x_phase": step["phase"],
                "x_step_order": index + 1,
            },
        }
        previous = action_id

    workflow[previous]["on_completion"] = end_id
    workflow[end_id] = {
        "type": "end",
        "name": "End " + playbook["playbook_name"],
    }

    return {
        "type": "playbook",
        "spec_version": "cacao-2.0",
        "id": "playbook--" + stable_uuid(playbook["playbook_id"]),
        "name": playbook["playbook_name"],
        "description": playbook["description"],
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "labels": ["generated", "attack-graph-generation"],
        "workflow_start": workflow_start,
        "workflow": workflow,
        "custom_properties": {
            "x_source_case": playbook["source_case"],
            "x_source_scenario_id": playbook.get("source_scenario_id", ""),
            "x_attack_path_id": playbook.get("attack_path_id", ""),
            "x_incident_index": playbook["incident_index"],
            "x_initial_risk": playbook["initial_risk"],
            "x_final_risk": playbook["final_risk"],
            "x_risk_reduction": playbook.get("risk_reduction", 0.0),
        },
    }


def incident_fingerprint(incident: list[dict[str, Any]]) -> str:
    payload = json.dumps(incident, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def cases_to_export(generation_source: Path, args: argparse.Namespace) -> list[str]:
    mulval_root = generation_source / "mulval-inputs"
    if args.all_cases:
        if not mulval_root.exists():
            raise FileNotFoundError(f"Missing MulVAL input directory: {mulval_root}")
        return sorted(path.name for path in mulval_root.iterdir() if path.is_dir())
    return args.case or ["NewTest"]


def main() -> None:
    args = parse_args()
    generation_source = repo_path(args.generation_source)
    output_dir = repo_path(args.output_dir)

    if not generation_source.exists():
        raise FileNotFoundError(f"Missing generation source directory: {generation_source}")
    if args.cve_table:
        cve_table = repo_path(args.cve_table)
        if not cve_table.exists():
            raise FileNotFoundError(f"Missing CVE table: {cve_table}")
        os.environ["CVE_MITRE_ENRICHED_PATH"] = str(cve_table)
    matplotlib_cache = repo_path("results/generated_repository/matplotlib-cache")
    matplotlib_cache.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(matplotlib_cache))

    add_generation_import_paths(generation_source)
    lookup = load_d3fend_lookup(generation_source)

    old_cwd = Path.cwd()
    os.chdir(generation_source)
    try:
        from Incident_generation.incidents import IncidentGenerator
        from Response_generation import extractDefenseKnowledge

        playbooks: list[dict[str, Any]] = []
        step_rows: list[dict[str, Any]] = []
        skipped_incidents: list[dict[str, Any]] = []

        for case in cases_to_export(generation_source, args):
            case_dir = generation_source / "mulval-inputs" / case
            profile = load_case_profile(case_dir)
            mulval_context = parse_mulval_context(case_dir)
            attack_graph = case_dir / "AttackGraph.xml"
            if not attack_graph.exists():
                raise FileNotFoundError(
                    "Missing AttackGraph.xml for case "
                    f"{case}. Expected: {attack_graph}. Run MulVAL first."
                )

            generator = IncidentGenerator(case)
            incidents = generator.get_goal_based_incidents()[: args.limit]

            for incident_index, incident in enumerate(incidents):
                try:
                    countermeasures, initial_risk, final_risk = (
                        extractDefenseKnowledge.create_countermeasure_table(incident)
                    )
                except Exception as exc:
                    skipped_incidents.append({
                        "case": case,
                        "incident_index": incident_index,
                        "error": str(exc),
                    })
                    continue
                if countermeasures.empty:
                    skipped_incidents.append({
                        "case": case,
                        "incident_index": incident_index,
                        "error": "No countermeasures returned.",
                    })
                    continue

                playbook_id = (
                    args.generated_prefix
                    + safe_id(case)
                    + "_"
                    + f"{incident_index:04d}"
                )
                fingerprint = incident_fingerprint(incident)
                playbook = {
                    "playbook_id": playbook_id,
                    "playbook_name": f"Generated response {case} #{incident_index}",
                    "description": (
                        "Generated from attack-graph-generation incident "
                        f"{case}/{incident_index}."
                    ),
                    "source_case": case,
                    "source_case_id": case,
                    "source_scenario_id": profile.get("scenario_id", "") or scenario_id_from_case(case),
                    "scenario_name": profile.get("scenario_name", "") or scenario_id_from_case(case).replace("_", " "),
                    "incident_index": incident_index,
                    "incident_fingerprint": fingerprint,
                    "attack_path_id": f"{case}:{incident_index:04d}:{fingerprint}",
                    "attacker_start": mulval_context["attacker_start"],
                    "attacker_goal": mulval_context["attacker_goal"],
                    "initial_risk": float(initial_risk),
                    "final_risk": float(final_risk),
                    "incident": incident,
                    "steps": [],
                }
                incident_lookup = incident_step_lookup(incident)

                records = []
                for _, row in countermeasures.iterrows():
                    record = {
                        key: normalize_scalar(value)
                        for key, value in row.to_dict().items()
                    }
                    phase_label = str(record.get("def_tactic_label", "")).strip()
                    records.append((PHASE_ORDER.get(phase_label, 99), record))

                for step_index, (_, record) in enumerate(sort_and_deduplicate_records(records), start=1):
                    label = str(record.get("def_tech_label", "")).strip()
                    ids = lookup.get(label, {})
                    defensive_id = ids.get("defensive_technique_id") or safe_id(label).replace("_", "")
                    phase_label = str(record.get("def_tactic_label", "")).strip()
                    phase = PHASE_NAMES.get(phase_label, phase_label or "Response")
                    step_id = f"{playbook_id}_s{step_index:02d}"
                    attack_id = attack_technique_id(record.get("off_tech_id", ""))
                    host = str(record.get("host", "")).strip()
                    incident_step = match_incident_step(incident_lookup, host, attack_id)
                    cve = str(incident_step.get("cve", "")).strip()
                    cvss_score = str(incident_step.get("cvss", "")).strip()
                    step = {
                        "playbook_id": playbook_id,
                        "playbook_name": playbook["playbook_name"],
                        "step_id": step_id,
                        "source": "generated",
                        "source_case_id": case,
                        "source_scenario_id": profile.get("scenario_id", "") or scenario_id_from_case(case),
                        "scenario_name": profile.get("scenario_name", "") or scenario_id_from_case(case).replace("_", " "),
                        "attack_path_id": playbook["attack_path_id"],
                        "step_name": f"{phase}: {label or defensive_id}",
                        "step_description": make_command(record),
                        "command": make_command(record),
                        "phase": phase,
                        "phase_label": phase_label,
                        "defensive_technique_label": label,
                        "defensive_technique_id": defensive_id,
                        "defense_relationship_label": record.get("def_artifact_rel_label", ""),
                        "defense_relationship_id": ids.get("defense_relationship_id", ""),
                        "defense_artifact_label": record.get("def_artifact_label", ""),
                        "defense_artifact_id": ids.get("defense_artifact_id", ""),
                        "offensive_artifact_label": record.get("off_artifact_label", ""),
                        "offensive_artifact_id": ids.get("offensive_artifact_id", ""),
                        "offensive_relationship_id": ids.get("offensive_relationship_id", ""),
                        "attack_technique_id": attack_id,
                        "attack_techniques": [attack_id] if attack_id else [],
                        "attack_technique_label": record.get("off_tech_label", ""),
                        "cve": cve,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity(cvss_score),
                        "risk_reduction": float(record.get("risk_reduction") or 0.0),
                        "host": host,
                        "host_binding": host,
                        "source_case": case,
                        "incident_index": incident_index,
                        "initial_risk": float(initial_risk),
                        "final_risk": float(final_risk),
                    }
                    step["missing_provenance_fields"] = missing_fields(step, PROVENANCE_STEP_FIELDS)
                    playbook["steps"].append(step)
                    step_rows.append(step)

                aggregate_playbook_provenance(playbook)
                playbooks.append(playbook)
    finally:
        os.chdir(old_cwd)

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / "generated_playbooks.jsonl", playbooks)
    missing_counts: dict[str, int] = {}
    missing_rows = []
    for playbook in playbooks:
        for field in playbook.get("missing_provenance_fields", []):
            missing_counts[f"playbook.{field}"] = missing_counts.get(f"playbook.{field}", 0) + 1
        missing_rows.append({
            "record_type": "playbook",
            "playbook_id": playbook["playbook_id"],
            "step_id": "",
            "missing_fields": join_multi(playbook.get("missing_provenance_fields", [])),
        })
        for step in playbook.get("steps", []):
            for field in step.get("missing_provenance_fields", []):
                missing_counts[f"step.{field}"] = missing_counts.get(f"step.{field}", 0) + 1
            missing_rows.append({
                "record_type": "step",
                "playbook_id": step["playbook_id"],
                "step_id": step["step_id"],
                "missing_fields": join_multi(step.get("missing_provenance_fields", [])),
            })

    write_json(output_dir / "summary.json", {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "playbooks": len(playbooks),
        "steps": len(step_rows),
        "skipped_incidents": len(skipped_incidents),
        "cases": sorted({pb["source_case"] for pb in playbooks}),
        "missing_provenance_counts": missing_counts,
    })
    write_json(output_dir / "skipped_incidents.json", skipped_incidents)
    write_csv(
        output_dir / "missing_provenance.csv",
        missing_rows,
        ["record_type", "playbook_id", "step_id", "missing_fields"],
    )

    fieldnames = [
        "playbook_id",
        "playbook_name",
        "source",
        "source_case_id",
        "source_scenario_id",
        "scenario_name",
        "attack_path_id",
        "attacker_start",
        "attacker_goal",
        "playbook_cves",
        "playbook_cvss_scores",
        "playbook_cvss_severities",
        "playbook_attack_techniques",
        "playbook_d3fend_techniques",
        "playbook_digital_artifacts",
        "affected_hosts",
        "host_bindings",
        "risk_before",
        "risk_after",
        "playbook_risk_reduction",
        "path_length",
        "action_count",
        "lifecycle_phases_present",
        "phase_completeness",
        "step_id",
        "step_name",
        "step_description",
        "command",
        "phase",
        "phase_label",
        "defensive_technique_label",
        "defensive_technique_id",
        "defense_relationship_label",
        "defense_relationship_id",
        "defense_artifact_label",
        "defense_artifact_id",
        "offensive_artifact_label",
        "offensive_artifact_id",
        "offensive_relationship_id",
        "attack_technique_id",
        "attack_techniques",
        "attack_technique_label",
        "cve",
        "cvss_score",
        "cvss_severity",
        "risk_reduction",
        "host",
        "host_binding",
        "source_case",
        "incident_index",
        "initial_risk",
        "final_risk",
        "missing_provenance_fields",
    ]
    playbooks_by_id = {playbook["playbook_id"]: playbook for playbook in playbooks}
    for row in step_rows:
        playbook = playbooks_by_id.get(row["playbook_id"], {})
        row["attacker_start"] = playbook.get("attacker_start", "")
        row["attacker_goal"] = playbook.get("attacker_goal", "")
        row["playbook_cves"] = join_multi(playbook.get("cves", []))
        row["playbook_cvss_scores"] = join_multi(playbook.get("cvss_scores", []))
        row["playbook_cvss_severities"] = join_multi(playbook.get("cvss_severities", []))
        row["playbook_attack_techniques"] = join_multi(playbook.get("attack_techniques", []))
        row["playbook_d3fend_techniques"] = join_multi(playbook.get("d3fend_techniques", []))
        row["playbook_digital_artifacts"] = join_multi(playbook.get("digital_artifacts", []))
        row["affected_hosts"] = join_multi(playbook.get("affected_hosts", []))
        row["host_bindings"] = json.dumps(playbook.get("host_bindings", {}), sort_keys=True)
        row["risk_before"] = playbook.get("risk_before", "")
        row["risk_after"] = playbook.get("risk_after", "")
        row["playbook_risk_reduction"] = playbook.get("risk_reduction", "")
        row["path_length"] = playbook.get("path_length", "")
        row["action_count"] = playbook.get("action_count", "")
        row["lifecycle_phases_present"] = join_multi(playbook.get("lifecycle_phases_present", []))
        row["phase_completeness"] = playbook.get("phase_completeness", "")
        row["attack_techniques"] = join_multi(row.get("attack_techniques", []))
        row["missing_provenance_fields"] = join_multi(row.get("missing_provenance_fields", []))
    write_csv(output_dir / "generated_playbook_steps.csv", step_rows, fieldnames)

    cacao_dir = output_dir / "cacao"
    cacao_dir.mkdir(parents=True, exist_ok=True)
    for playbook in playbooks:
        path = cacao_dir / f"{playbook['playbook_id']}.json"
        write_json(path, cacao_playbook(playbook))

    print(f"Wrote {len(playbooks)} playbooks and {len(step_rows)} steps to {output_dir}")


if __name__ == "__main__":
    main()
