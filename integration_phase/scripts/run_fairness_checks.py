#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

try:
    from rdflib import Graph, Namespace
except ModuleNotFoundError:
    Graph = Namespace = None

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    classify_playbook,
    expected_source_case_id,
    expected_source_scenario_id,
    read_csv_dicts,
    repo_display_path,
    repo_path,
    safe_id,
    split_multi,
    split_playbook_ids,
    to_float,
    write_csv,
    write_json,
)


IRSO = Namespace("http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#") if Namespace else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check fairness and leakage invariants for closed-loop generated playbook evaluation."
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation"),
        help="Evaluation output directory.",
    )
    parser.add_argument(
        "--mode",
        default="augmented-reduced",
        help="Main closed-loop mode to inspect.",
    )
    parser.add_argument(
        "--community-mode",
        default="community-only",
        help="Community baseline mode to inspect.",
    )
    parser.add_argument(
        "--generated-owl",
        type=Path,
        default=Path("results/generated_repository/reduced_generated_playbooks.owl"),
        help="Generated playbook OWL containing playbook and step ATT&CK provenance.",
    )
    parser.add_argument(
        "--generated-prefix",
        default="ma_",
        help="Generated playbook ID prefix.",
    )
    parser.add_argument("--allow-cross-scenario-generated", action="store_true")
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("results/evaluation/diagnostics/fairness_checks.json"),
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("results/evaluation/diagnostics/fairness_checks_by_scenario.csv"),
    )
    return parser.parse_args()


def read_json(path: Path) -> Any:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def candidate_path(evaluation_dir: Path, mode: str, scenario: str) -> Path:
    return evaluation_dir / mode / "candidate_scores_per_scenario" / f"{scenario}_candidate_scores.csv"


def coverage_path(evaluation_dir: Path, mode: str, scenario: str, kind: str) -> Path:
    return evaluation_dir / mode / "mcdm_scores_per_scenario" / f"{scenario}_{kind}_attack_coverage.json"


def selection_path(evaluation_dir: Path, mode: str) -> Path:
    return evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv"


def rows_by_scenario(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    return {
        row["Scenario"]: row
        for row in read_csv_dicts(path)
        if row.get("Scenario") and row.get("Scenario") != "Average"
    }


def scenario_matches(row: dict[str, str], scenario: str, generated_prefix: str) -> bool:
    expected_case = expected_source_case_id(scenario)
    expected_scenario = expected_source_scenario_id(scenario)
    cases = split_multi(row.get("source_case_id", ""))
    scenarios = split_multi(row.get("source_scenario_id", ""))
    playbook_id = row.get("playbook_id", "")
    if expected_case in cases or expected_scenario in scenarios:
        return True
    if not cases and not scenarios and playbook_id.startswith(f"{generated_prefix}scenario_{safe_id(scenario)}_"):
        return True
    return False


def first_selected_id(row: dict[str, str]) -> str:
    ids = split_playbook_ids(row.get("Top_MCDM_Playbook", ""))
    return ids[0] if ids else ""


def replay_selected_ids(rows: list[dict[str, str]]) -> set[str]:
    if not rows:
        return set()
    max_score = max(to_float(row.get("total_score"), -1.0) for row in rows)
    return {
        row.get("playbook_id", "")
        for row in rows
        if to_float(row.get("total_score"), -1.0) == max_score and row.get("playbook_id")
    }


def load_owl_attack_equality(owl_path: Path) -> tuple[dict[str, bool], dict[str, dict[str, int]], dict[str, Any]]:
    if not owl_path.exists():
        return {}, {}, {"available": False, "reason": f"missing {repo_display_path(owl_path)}"}

    rdf_resource = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource"
    rdf_about = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about"
    irso = "{http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#}"

    try:
        tree = ET.parse(owl_path)
    except ET.ParseError as exc:
        return {}, {}, {"available": False, "reason": f"could not parse RDF/XML: {exc}"}

    playbook_subject_by_id: dict[str, str] = {}
    playbook_covers_by_subject: dict[str, set[str]] = defaultdict(set)
    playbook_steps_by_subject: dict[str, set[str]] = defaultdict(set)
    step_attacks_by_subject: dict[str, set[str]] = defaultdict(set)

    for description in tree.getroot():
        subject = description.attrib.get(rdf_about, "")
        if not subject:
            continue
        playbook_id = ""
        for child in description:
            if child.tag == f"{irso}hasPlaybookID" and child.text:
                playbook_id = child.text.strip()
            elif child.tag == f"{irso}coversAttackTechnique":
                resource = child.attrib.get(rdf_resource, "")
                if resource:
                    playbook_covers_by_subject[subject].add(resource)
            elif child.tag == f"{irso}hasStep":
                resource = child.attrib.get(rdf_resource, "")
                if resource:
                    playbook_steps_by_subject[subject].add(resource)
            elif child.tag == f"{irso}generatedForAttackTechnique":
                resource = child.attrib.get(rdf_resource, "")
                if resource:
                    step_attacks_by_subject[subject].add(resource)
        if playbook_id:
            playbook_subject_by_id[playbook_id] = subject

    equality: dict[str, bool] = {}
    counts: dict[str, dict[str, int]] = {}
    mismatches = 0
    for playbook_id, subject in playbook_subject_by_id.items():
        step_attack_set = set()
        for step_subject in playbook_steps_by_subject.get(subject, set()):
            step_attack_set.update(step_attacks_by_subject.get(step_subject, set()))
        covers_set = playbook_covers_by_subject.get(subject, set())
        if step_attack_set:
            equal = covers_set == step_attack_set
            equality[playbook_id] = equal
            if not equal:
                mismatches += 1
            counts[playbook_id] = {
                "step_generated_for_count": len(step_attack_set),
                "playbook_covers_count": len(covers_set),
                "missing_playbook_covers_count": len(step_attack_set - covers_set),
                "extra_playbook_covers_count": len(covers_set - step_attack_set),
            }

    return equality, counts, {
        "available": True,
        "parser": "xml.etree.ElementTree",
        "generated_playbooks_with_step_attack_provenance": len(equality),
        "playbook_step_attack_mismatches": mismatches,
    }


def selected_candidate(rows: list[dict[str, str]], selected_id: str) -> dict[str, str]:
    return next((row for row in rows if row.get("playbook_id") == selected_id), {})


def summarize_bool(rows: list[dict[str, Any]], field: str) -> dict[str, Any]:
    values = [row.get(field) == "True" for row in rows if row.get(field) != ""]
    return {
        "passed": all(values) if values else False,
        "passed_count": sum(values),
        "checked_count": len(values),
    }


def main() -> None:
    args = parse_args()
    evaluation_dir = repo_path(args.evaluation_dir)
    generated_owl = repo_path(args.generated_owl)
    out_json = repo_path(args.out_json)
    out_csv = repo_path(args.out_csv)

    selection_rows = rows_by_scenario(selection_path(evaluation_dir, args.mode))
    community_selection_rows = rows_by_scenario(selection_path(evaluation_dir, args.community_mode))
    owl_equality, owl_counts, owl_summary = load_owl_attack_equality(generated_owl)

    by_scenario_rows: list[dict[str, Any]] = []
    source_counter = Counter()

    for scenario in DEFAULT_SCENARIOS:
        path = candidate_path(evaluation_dir, args.mode, scenario)
        rows = read_csv_dicts(path) if path.exists() else []
        selection = selection_rows.get(scenario, {})
        selected_id = first_selected_id(selection)
        selected = selected_candidate(rows, selected_id)

        generated_rows = [row for row in rows if row.get("candidate_source") == "generated"]
        community_rows = [row for row in rows if row.get("candidate_source") == "community"]
        source_counter.update(row.get("candidate_source", "") for row in rows)

        wrong_generated = [
            row.get("playbook_id", "")
            for row in generated_rows
            if not scenario_matches(row, scenario, args.generated_prefix)
        ]
        generated_match = args.allow_cross_scenario_generated or not wrong_generated

        direct_coverage = read_json(coverage_path(evaluation_dir, args.mode, scenario, "direct"))
        scenario_attack_count = int(to_float(selection.get("Scenario_Attack_Count"), 0.0))
        generated_direct_full = [
            row.get("playbook_id", "")
            for row in generated_rows
            if len(direct_coverage.get(row.get("playbook_id", ""), [])) >= scenario_attack_count > 0
        ]
        community_with_direct = [
            row.get("playbook_id", "")
            for row in community_rows
            if direct_coverage.get(row.get("playbook_id", ""))
        ]
        direct_not_copied = not generated_rows or len(generated_direct_full) < len(generated_rows)
        direct_only_generated = not community_with_direct

        owl_available = bool(owl_summary.get("available"))
        owl_mismatches = [
            row.get("playbook_id", "")
            for row in generated_rows
            if owl_equality and owl_equality.get(row.get("playbook_id", ""), True) is False
        ]

        community_candidate_path = candidate_path(evaluation_dir, args.community_mode, scenario)
        community_candidate_rows = read_csv_dicts(community_candidate_path) if community_candidate_path.exists() else []
        community_selection = community_selection_rows.get(scenario, {})
        community_selected = set(split_playbook_ids(community_selection.get("Top_MCDM_Playbook", "")))
        replayed_community = replay_selected_ids(community_candidate_rows)
        community_has_no_generated = all(
            row.get("candidate_source") != "generated"
            for row in community_candidate_rows
        ) and community_selection.get("candidate_source") in {"", "community"}
        community_replay_matches = bool(community_selected) and community_selected == replayed_community
        community_unchanged = community_has_no_generated and community_replay_matches

        selected_source = selected.get("candidate_source") or selection.get("candidate_source", "")
        row = {
            "Scenario": scenario,
            "mode": args.mode,
            "selected_source": selected_source,
            "selected_playbook_id": selected_id,
            "selected_source_case_id": selected.get("source_case_id") or selection.get("source_case_id", ""),
            "selected_attack_path_id": selected.get("attack_path_id") or selection.get("attack_path_id", ""),
            "selected_risk_reduction": selected.get("raw_risk_reduction") or selection.get("selected_risk_reduction", ""),
            "selected_action_count": selected.get("action_count") or selection.get("selected_action_count", ""),
            "selected_direct_attack_recall": selected.get("direct_attack_recall") or selection.get("direct_attack_recall", ""),
            "selected_inferred_attack_recall": selected.get("inferred_attack_recall") or selection.get("inferred_attack_recall", ""),
            "selected_combined_attack_recall": selected.get("combined_attack_recall") or selection.get("combined_attack_recall", ""),
            "generated_candidate_count": len(generated_rows),
            "community_candidate_count": len(community_rows),
            "candidate_count": len(rows),
            "generated_match_scenario": str(generated_match),
            "wrong_scenario_generated_count": len(wrong_generated),
            "wrong_scenario_generated_examples": ";".join(wrong_generated[:5]),
            "direct_links_only_generated": str(direct_only_generated),
            "community_direct_link_count": len(community_with_direct),
            "direct_links_not_full_target_copied": str(direct_not_copied),
            "generated_full_direct_coverage_count": len(generated_direct_full),
            "playbook_covers_equals_step_generated_for": str(owl_available and not owl_mismatches),
            "owl_attack_mismatch_count": len(owl_mismatches),
            "owl_attack_mismatch_examples": ";".join(owl_mismatches[:5]),
            "community_only_no_generated_candidates": str(community_has_no_generated),
            "community_only_replay_matches_selection": str(community_replay_matches),
            "community_only_unchanged_invariant": str(community_unchanged),
            "augmented_reduced_includes_community_candidates": str(len(community_rows) > 0),
        }
        for key, value in owl_counts.get(selected_id, {}).items():
            row[f"selected_{key}"] = value
        by_scenario_rows.append(row)

    fieldnames = [
        "Scenario",
        "mode",
        "selected_source",
        "selected_playbook_id",
        "selected_source_case_id",
        "selected_attack_path_id",
        "selected_risk_reduction",
        "selected_action_count",
        "selected_direct_attack_recall",
        "selected_inferred_attack_recall",
        "selected_combined_attack_recall",
        "generated_candidate_count",
        "community_candidate_count",
        "candidate_count",
        "generated_match_scenario",
        "wrong_scenario_generated_count",
        "wrong_scenario_generated_examples",
        "direct_links_only_generated",
        "community_direct_link_count",
        "direct_links_not_full_target_copied",
        "generated_full_direct_coverage_count",
        "playbook_covers_equals_step_generated_for",
        "owl_attack_mismatch_count",
        "owl_attack_mismatch_examples",
        "community_only_no_generated_candidates",
        "community_only_replay_matches_selection",
        "community_only_unchanged_invariant",
        "augmented_reduced_includes_community_candidates",
        "selected_step_generated_for_count",
        "selected_playbook_covers_count",
        "selected_missing_playbook_covers_count",
        "selected_extra_playbook_covers_count",
    ]

    checks = {
        "generated_playbooks_only_match_scenario": summarize_bool(by_scenario_rows, "generated_match_scenario"),
        "direct_attack_links_only_generated": summarize_bool(by_scenario_rows, "direct_links_only_generated"),
        "direct_attack_links_not_full_target_copied": summarize_bool(by_scenario_rows, "direct_links_not_full_target_copied"),
        "playbook_covers_equals_step_generated_for": summarize_bool(by_scenario_rows, "playbook_covers_equals_step_generated_for"),
        "community_only_unchanged_invariant": summarize_bool(by_scenario_rows, "community_only_unchanged_invariant"),
        "augmented_reduced_includes_community": summarize_bool(by_scenario_rows, "augmented_reduced_includes_community_candidates"),
    }
    passed = sum(1 for check in checks.values() if check["passed"])

    write_csv(out_csv, by_scenario_rows, fieldnames)
    write_json(out_json, {
        "mode": args.mode,
        "community_mode": args.community_mode,
        "allow_cross_scenario_generated": args.allow_cross_scenario_generated,
        "checks_passed": passed,
        "checks_failed": len(checks) - passed,
        "checks": checks,
        "candidate_source_counts": dict(source_counter),
        "owl_attack_coverage_summary": owl_summary,
        "by_scenario_csv": repo_display_path(out_csv),
    })
    print(f"Wrote fairness checks to {out_json}")
    print(f"Wrote per-scenario fairness checks to {out_csv}")


if __name__ == "__main__":
    main()
