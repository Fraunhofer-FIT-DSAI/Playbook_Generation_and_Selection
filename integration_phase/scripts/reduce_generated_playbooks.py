#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from rdflib import Graph, Literal, Namespace
except ModuleNotFoundError:
    Graph = Literal = Namespace = None

from closed_loop_common import (
    join_multi,
    read_csv_dicts,
    repo_path,
    safe_id,
    split_multi,
    to_float,
    write_csv,
    write_json,
)


IRSO = Namespace("http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#") if Namespace else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reduce generated playbook candidate pools per scenario."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("results/generated_repository/generated_playbooks_manifest.csv"),
        help="Manifest produced by generated_playbooks_to_owl.py.",
    )
    parser.add_argument(
        "--owl",
        type=Path,
        default=Path("results/generated_repository/generated_playbooks.owl"),
        help="Generated playbook OWL produced by generated_playbooks_to_owl.py.",
    )
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=Path("data/scenario_profiles"),
        help="Scenario profile directory. Used for scenario identity consistency only.",
    )
    parser.add_argument(
        "--strategy",
        choices=["top-risk", "diverse", "pareto", "hybrid"],
        default="hybrid",
        help="Reduction strategy.",
    )
    parser.add_argument(
        "--per-scenario",
        type=int,
        default=50,
        help="Maximum retained generated playbooks per scenario.",
    )
    parser.add_argument(
        "--out-manifest",
        type=Path,
        default=Path("results/generated_repository/reduced_generated_playbooks_manifest.csv"),
    )
    parser.add_argument(
        "--out-owl",
        type=Path,
        default=Path("results/generated_repository/reduced_generated_playbooks.owl"),
    )
    parser.add_argument(
        "--report-csv",
        type=Path,
        default=Path("results/generated_repository/reduction_report.csv"),
    )
    parser.add_argument(
        "--summary-json",
        type=Path,
        default=Path("results/generated_repository/reduction_summary.json"),
    )
    return parser.parse_args()


def require_rdflib() -> None:
    if Graph is None:
        raise RuntimeError("Missing dependency: rdflib. Install dependencies with `pip install -r requirements.txt`.")


def aggregate_manifest(rows: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    playbooks: dict[str, dict[str, Any]] = {}
    for row in rows:
        playbook_id = row.get("playbook_id", "").strip()
        if not playbook_id:
            continue
        item = playbooks.setdefault(playbook_id, {
            "playbook_id": playbook_id,
            "rows": [],
            "source": row.get("source", "generated") or "generated",
            "source_case_id": row.get("source_case_id") or row.get("source_case", ""),
            "source_scenario_id": row.get("source_scenario_id", ""),
            "scenario_name": row.get("scenario_name", ""),
            "attack_path_id": row.get("attack_path_id", ""),
            "attack_techniques": set(),
            "cves": set(),
            "d3fend_techniques": set(),
            "artifacts": set(),
            "phases": set(),
            "hosts": set(),
            "risk_reduction": to_float(row.get("playbook_risk_reduction") or row.get("risk_reduction"), 0.0),
            "phase_completeness": to_float(row.get("phase_completeness"), 0.0),
            "action_count": int(to_float(row.get("action_count"), 0.0)) if row.get("action_count") else 0,
        })
        item["rows"].append(row)
        for field, target in [
            ("playbook_attack_techniques", "attack_techniques"),
            ("attack_techniques", "attack_techniques"),
            ("attack_technique_id", "attack_techniques"),
            ("playbook_cves", "cves"),
            ("cve", "cves"),
            ("playbook_d3fend_techniques", "d3fend_techniques"),
            ("defensive_technique_id", "d3fend_techniques"),
            ("playbook_digital_artifacts", "artifacts"),
            ("defense_artifact_id", "artifacts"),
            ("lifecycle_phases_present", "phases"),
            ("phase", "phases"),
            ("affected_hosts", "hosts"),
            ("host_binding", "hosts"),
        ]:
            item[target].update(split_multi(row.get(field, "")))
        item["risk_reduction"] = max(
            item["risk_reduction"],
            to_float(row.get("playbook_risk_reduction") or row.get("risk_reduction"), 0.0),
        )
        if row.get("action_count"):
            item["action_count"] = max(item["action_count"], int(to_float(row.get("action_count"), 0.0)))
        else:
            item["action_count"] = max(item["action_count"], len(item["rows"]))
        item["phase_completeness"] = max(item["phase_completeness"], to_float(row.get("phase_completeness"), 0.0))
    return playbooks


def scenario_key(item: dict[str, Any]) -> str:
    if item.get("source_scenario_id"):
        return str(item["source_scenario_id"])
    case_id = str(item.get("source_case_id", ""))
    if case_id.startswith("scenario_"):
        return case_id.removeprefix("scenario_")
    return safe_id(item.get("scenario_name", "") or case_id or "unknown")


def semantic_signature(item: dict[str, Any]) -> tuple[tuple[str, ...], ...]:
    return (
        tuple(sorted(item["attack_techniques"])),
        tuple(sorted(item["cves"])),
        tuple(sorted(item["d3fend_techniques"])),
        tuple(sorted(item["artifacts"])),
        tuple(sorted(item["phases"])),
    )


def ranking_tuple(item: dict[str, Any]) -> tuple[float, int, int, int, float, int]:
    return (
        float(item["risk_reduction"]),
        len(item["attack_techniques"]),
        len(item["d3fend_techniques"]),
        len(item["artifacts"]),
        float(item["phase_completeness"]),
        -int(item["action_count"] or 0),
    )


def dominates(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_values = [
        float(left["risk_reduction"]),
        len(left["attack_techniques"]),
        len(left["artifacts"]),
        float(left["phase_completeness"]),
        -int(left["action_count"] or 0),
    ]
    right_values = [
        float(right["risk_reduction"]),
        len(right["attack_techniques"]),
        len(right["artifacts"]),
        float(right["phase_completeness"]),
        -int(right["action_count"] or 0),
    ]
    return all(l >= r for l, r in zip(left_values, right_values)) and any(l > r for l, r in zip(left_values, right_values))


def pareto_front(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    front = []
    for item in items:
        if not any(dominates(other, item) for other in items if other is not item):
            front.append(item)
    return front


def diverse_representatives(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_signature: dict[tuple[tuple[str, ...], ...], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        by_signature[semantic_signature(item)].append(item)
    reps = []
    for group in by_signature.values():
        reps.append(sorted(group, key=ranking_tuple, reverse=True)[0])
    return reps


def reduce_items(items: list[dict[str, Any]], strategy: str, limit: int) -> list[dict[str, Any]]:
    if strategy == "top-risk":
        candidates = items
    elif strategy == "diverse":
        candidates = diverse_representatives(items)
    elif strategy == "pareto":
        candidates = pareto_front(items)
    else:
        candidates = pareto_front(diverse_representatives(items))

    ranked = sorted(candidates, key=ranking_tuple, reverse=True)
    if limit > 0 and len(ranked) > limit:
        ranked = ranked[:limit]
    return ranked


def write_reduced_owl(input_owl: Path, output_owl: Path, selected_ids: set[str]) -> None:
    require_rdflib()
    graph = Graph()
    graph.parse(input_owl)

    playbook_subjects = set()
    for subject, _predicate, obj in graph.triples((None, IRSO.hasPlaybookID, None)):
        if str(obj) in selected_ids:
            playbook_subjects.add(subject)

    step_subjects = set()
    for playbook in playbook_subjects:
        for _subject, _predicate, step in graph.triples((playbook, IRSO.hasStep, None)):
            step_subjects.add(step)

    reduced = Graph()
    for prefix, namespace in graph.namespaces():
        reduced.bind(prefix, namespace)

    subjects = playbook_subjects | step_subjects
    for subject in subjects:
        for triple in graph.triples((subject, None, None)):
            reduced.add(triple)
    for playbook in playbook_subjects:
        reduced.add((playbook, IRSO.inCandidatePool, Literal("reduced")))

    output_owl.parent.mkdir(parents=True, exist_ok=True)
    reduced.serialize(destination=output_owl, format="xml")


def main() -> None:
    args = parse_args()
    manifest = repo_path(args.manifest)
    input_owl = repo_path(args.owl)
    out_manifest = repo_path(args.out_manifest)
    out_owl = repo_path(args.out_owl)
    report_csv = repo_path(args.report_csv)
    summary_json = repo_path(args.summary_json)

    rows = read_csv_dicts(manifest)
    playbooks = aggregate_manifest(rows)
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in playbooks.values():
        by_scenario[scenario_key(item)].append(item)

    selected_ids: set[str] = set()
    report_rows = []
    for scenario, items in sorted(by_scenario.items()):
        selected = reduce_items(items, args.strategy, args.per_scenario)
        scenario_selected_ids = {item["playbook_id"] for item in selected}
        selected_ids.update(scenario_selected_ids)
        ranked_all = sorted(items, key=ranking_tuple, reverse=True)
        for rank, item in enumerate(ranked_all, start=1):
            report_rows.append({
                "source_scenario_id": scenario,
                "playbook_id": item["playbook_id"],
                "kept": str(item["playbook_id"] in scenario_selected_ids),
                "rank": rank,
                "strategy": args.strategy,
                "risk_reduction": f"{float(item['risk_reduction']):.6f}",
                "direct_attack_count": len(item["attack_techniques"]),
                "d3fend_count": len(item["d3fend_techniques"]),
                "artifact_count": len(item["artifacts"]),
                "phase_completeness": f"{float(item['phase_completeness']):.6f}",
                "action_count": item["action_count"],
                "semantic_signature": "|".join(join_multi(part) for part in semantic_signature(item)),
            })

    reduced_rows = [row for row in rows if row.get("playbook_id", "").strip() in selected_ids]
    write_csv(out_manifest, reduced_rows, list(rows[0].keys()) if rows else [])
    write_reduced_owl(input_owl, out_owl, selected_ids)
    write_csv(
        report_csv,
        report_rows,
        [
            "source_scenario_id",
            "playbook_id",
            "kept",
            "rank",
            "strategy",
            "risk_reduction",
            "direct_attack_count",
            "d3fend_count",
            "artifact_count",
            "phase_completeness",
            "action_count",
            "semantic_signature",
        ],
    )
    write_json(summary_json, {
        "strategy": args.strategy,
        "per_scenario": args.per_scenario,
        "input_playbooks": len(playbooks),
        "selected_playbooks": len(selected_ids),
        "scenarios": {
            scenario: {
                "input_playbooks": len(items),
                "selected_playbooks": sum(1 for item in items if item["playbook_id"] in selected_ids),
            }
            for scenario, items in sorted(by_scenario.items())
        },
        "out_manifest": str(out_manifest),
        "out_owl": str(out_owl),
    })
    print(f"Selected {len(selected_ids)} of {len(playbooks)} generated playbooks")
    print(f"Wrote reduced manifest to {out_manifest}")
    print(f"Wrote reduced OWL to {out_owl}")


if __name__ == "__main__":
    main()
