#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

try:
    from rdflib import Graph, Namespace
except ModuleNotFoundError:
    Graph = Namespace = None

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    EVALUATION_MODES,
    expected_source_case_id,
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
IRSO_NS = "http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#"
RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run closed-loop integration sanity checks.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/"
            "reduced_generated_playbooks_manifest.csv"
        ),
    )
    parser.add_argument(
        "--generated-owl",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/"
            "reduced_generated_playbooks.owl"
        ),
    )
    parser.add_argument(
        "--reduced-manifest",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/"
            "reduced_generated_playbooks_manifest.csv"
        ),
    )
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
    )
    parser.add_argument("--per-scenario", type=int, default=50)
    parser.add_argument("--allow-cross-scenario-generated", action="store_true")
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("results/evaluation/corrected/sanity_summary.json"),
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("results/evaluation/corrected/sanity_checks.csv"),
    )
    return parser.parse_args()


def add_check(rows: list[dict[str, Any]], check: str, passed: bool, details: str = "") -> None:
    rows.append({
        "check": check,
        "passed": str(passed),
        "details": details,
    })


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_manifest(rows: list[dict[str, Any]], manifest: Path) -> dict[str, list[dict[str, str]]]:
    if not manifest.exists():
        add_check(rows, "generated_manifest_exists", False, repo_display_path(manifest))
        return {}
    manifest_rows = read_csv_dicts(manifest)
    add_check(rows, "generated_manifest_exists", True, repo_display_path(manifest))

    by_playbook: dict[str, list[dict[str, str]]] = defaultdict(list)
    step_ids = Counter()
    for row in manifest_rows:
        playbook_id = row.get("playbook_id", "")
        step_id = row.get("step_id", "")
        if playbook_id:
            by_playbook[playbook_id].append(row)
        if step_id:
            step_ids[step_id] += 1

    missing_scenario = [
        playbook_id for playbook_id, playbook_rows in by_playbook.items()
        if not any(row.get("source_scenario_id") for row in playbook_rows)
    ]
    add_check(
        rows,
        "every_generated_playbook_has_source_scenario_id",
        not missing_scenario,
        f"missing={len(missing_scenario)}",
    )
    duplicate_steps = [step_id for step_id, count in step_ids.items() if count > 1]
    add_check(rows, "no_duplicate_generated_step_ids", not duplicate_steps, f"duplicates={len(duplicate_steps)}")
    return by_playbook


def check_owl_attack_coverage(rows: list[dict[str, Any]], owl_path: Path) -> None:
    if not owl_path.exists():
        add_check(rows, "generated_owl_exists", False, repo_display_path(owl_path))
        return
    if Graph is None:
        check_owl_attack_coverage_xml(rows, owl_path)
        return

    graph = Graph()
    graph.parse(owl_path)
    step_attack_by_playbook: dict[Any, set[Any]] = defaultdict(set)
    playbook_attack: dict[Any, set[Any]] = defaultdict(set)
    for playbook, _predicate, step in graph.triples((None, IRSO.hasStep, None)):
        for _step, _p, attack in graph.triples((step, IRSO.generatedForAttackTechnique, None)):
            step_attack_by_playbook[playbook].add(attack)
    for playbook in step_attack_by_playbook:
        for _playbook, _p, attack in graph.triples((playbook, IRSO.coversAttackTechnique, None)):
            playbook_attack[playbook].add(attack)
    missing = {
        playbook: attacks - playbook_attack.get(playbook, set())
        for playbook, attacks in step_attack_by_playbook.items()
        if attacks - playbook_attack.get(playbook, set())
    }
    add_check(
        rows,
        "playbook_level_attack_coverage_matches_steps",
        not missing,
        f"playbooks_missing_coverage={len(missing)}",
    )


def resource_value(element: ET.Element) -> str:
    return element.attrib.get(f"{{{RDF_NS}}}resource", "")


def check_owl_attack_coverage_xml(rows: list[dict[str, Any]], owl_path: Path) -> None:
    """Fallback for the generated RDF/XML export when rdflib is unavailable."""
    try:
        root = ET.parse(owl_path).getroot()
    except ET.ParseError as exc:
        add_check(rows, "playbook_level_attack_coverage_matches_steps", False, f"XML parse error: {exc}")
        return

    descriptions = root.findall(f"{{{RDF_NS}}}Description")
    step_attack: dict[str, set[str]] = defaultdict(set)
    playbook_steps: dict[str, set[str]] = defaultdict(set)
    playbook_attack: dict[str, set[str]] = defaultdict(set)

    for description in descriptions:
        subject = description.attrib.get(f"{{{RDF_NS}}}about", "")
        if not subject:
            continue
        for child in description:
            if child.tag == f"{{{IRSO_NS}}}generatedForAttackTechnique":
                attack = resource_value(child)
                if attack:
                    step_attack[subject].add(attack)
            elif child.tag == f"{{{IRSO_NS}}}hasStep":
                step = resource_value(child)
                if step:
                    playbook_steps[subject].add(step)
            elif child.tag == f"{{{IRSO_NS}}}coversAttackTechnique":
                attack = resource_value(child)
                if attack:
                    playbook_attack[subject].add(attack)

    missing = {}
    for playbook, steps in playbook_steps.items():
        attacks = set().union(*(step_attack.get(step, set()) for step in steps))
        uncovered = attacks - playbook_attack.get(playbook, set())
        if uncovered:
            missing[playbook] = uncovered
    add_check(
        rows,
        "playbook_level_attack_coverage_matches_steps",
        not missing,
        f"playbooks_missing_coverage={len(missing)}; parser=xml",
    )


def check_reduced_pool(rows: list[dict[str, Any]], reduced_manifest: Path, limit: int) -> None:
    if not reduced_manifest.exists():
        add_check(rows, "reduced_manifest_exists", False, repo_display_path(reduced_manifest))
        return
    reduced_rows = read_csv_dicts(reduced_manifest)
    by_scenario: dict[str, set[str]] = defaultdict(set)
    for row in reduced_rows:
        scenario = row.get("source_scenario_id") or safe_id(row.get("scenario_name", "")) or "unknown"
        playbook_id = row.get("playbook_id", "")
        if playbook_id:
            by_scenario[scenario].add(playbook_id)
    over_limit = {scenario: len(ids) for scenario, ids in by_scenario.items() if limit > 0 and len(ids) > limit}
    add_check(rows, "reduced_pool_at_most_n_per_scenario", not over_limit, str(over_limit))


def check_selection_outputs(rows: list[dict[str, Any]], evaluation_dir: Path, allow_cross_scenario: bool) -> None:
    required_columns = {"DC", "DAC", "DTC", "TC", "RC", "CC", "AC"}
    recall_columns = {
        "combined_attack_recall",
        "achievable_combined_attack_recall",
        "normalized_combined_attack_recall",
    }
    for mode in ["community-only", "generated-reduced", "augmented-reduced"]:
        path = evaluation_dir / mode / f"scenario_playbook_evaluation_{mode}.csv"
        add_check(rows, f"{mode}_selection_output_exists", path.exists(), repo_display_path(path))
        if path.exists():
            csv_rows = read_csv_dicts(path)
            scenario_rows = [
                row for row in csv_rows
                if row.get("Scenario") and row.get("Scenario") != "Average"
            ]
            columns = set(csv_rows[0].keys()) if csv_rows else set()
            scenario_names = [row.get("Scenario", "") for row in scenario_rows]
            add_check(
                rows,
                f"{mode}_has_exactly_16_scenarios",
                len(scenario_rows) == len(DEFAULT_SCENARIOS)
                and sorted(scenario_names) == sorted(DEFAULT_SCENARIOS),
                f"rows={len(scenario_rows)}; missing={sorted(set(DEFAULT_SCENARIOS) - set(scenario_names))}; "
                f"extra={sorted(set(scenario_names) - set(DEFAULT_SCENARIOS))}",
            )
            add_check(
                rows,
                f"{mode}_has_all_scoring_columns",
                required_columns <= columns,
                f"missing={sorted(required_columns - columns)}",
            )
            add_check(
                rows,
                f"{mode}_has_normalized_recall_columns",
                recall_columns <= columns,
                f"missing={sorted(recall_columns - columns)}",
            )

            invalid_recall_rows = []
            non_union_rows = []
            above_achievable_rows = []
            invalid_normalized_rows = []
            tie_mismatches = []
            non_single_winners = []
            for selection in scenario_rows:
                scenario = selection.get("Scenario", "")
                direct = to_float(selection.get("direct_attack_recall"), -1.0)
                inferred = to_float(selection.get("inferred_attack_recall"), -1.0)
                combined = to_float(selection.get("combined_attack_recall"), -1.0)
                achievable = to_float(selection.get("achievable_combined_attack_recall"), -1.0)
                normalized = to_float(selection.get("normalized_combined_attack_recall"), -1.0)
                if any(value < -1e-12 or value > 1.0 + 1e-12 for value in (direct, inferred, combined, achievable)):
                    invalid_recall_rows.append(scenario)
                if combined + 1e-12 < max(direct, inferred) or combined > direct + inferred + 1e-12:
                    non_union_rows.append(scenario)
                if combined > achievable + 1e-12:
                    above_achievable_rows.append(scenario)
                expected_normalized = combined / achievable if achievable > 0 else 0.0
                if (
                    normalized < -1e-12
                    or normalized > 1.0 + 1e-12
                    or abs(normalized - expected_normalized) > 1e-9
                ):
                    invalid_normalized_rows.append(scenario)

                selected_ids = split_playbook_ids(selection.get("Top_MCDM_Playbook", ""))
                if len(selected_ids) != 1:
                    non_single_winners.append(scenario)
                    continue
                candidate_path = (
                    evaluation_dir / mode / "candidate_scores_per_scenario"
                    / f"{scenario}_candidate_scores.csv"
                )
                candidate_rows = read_csv_dicts(candidate_path) if candidate_path.exists() else []
                if not candidate_rows:
                    tie_mismatches.append(f"{scenario}:missing candidate table")
                    continue
                max_score = max(to_float(row.get("total_score"), -1.0) for row in candidate_rows)
                expected_id = min(
                    row.get("playbook_id", "")
                    for row in candidate_rows
                    if abs(to_float(row.get("total_score"), -1.0) - max_score) <= 1e-12
                    and row.get("playbook_id")
                )
                if selected_ids[0] != expected_id:
                    tie_mismatches.append(f"{scenario}:{selected_ids[0]}!={expected_id}")

            add_check(rows, f"{mode}_recall_values_within_bounds", not invalid_recall_rows, str(invalid_recall_rows))
            add_check(rows, f"{mode}_combined_recall_is_union_compatible", not non_union_rows, str(non_union_rows))
            add_check(rows, f"{mode}_combined_not_above_achievable", not above_achievable_rows, str(above_achievable_rows))
            add_check(rows, f"{mode}_normalized_recall_consistent", not invalid_normalized_rows, str(invalid_normalized_rows))
            add_check(rows, f"{mode}_exactly_one_winner_per_scenario", not non_single_winners, str(non_single_winners))
            add_check(rows, f"{mode}_winner_matches_declared_tie_policy", not tie_mismatches, str(tie_mismatches))

            summary_path = evaluation_dir / mode / "selection_summary.json"
            summary_text = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
            historical_manifest_reference = (
                "results/generated_repository/reduced_generated_playbooks_manifest.csv"
                in summary_text
            )
            add_check(
                rows,
                f"{mode}_does_not_reference_historical_manifest",
                not historical_manifest_reference,
                repo_display_path(summary_path),
            )

    for mode in EVALUATION_MODES:
        candidate_dir = evaluation_dir / mode / "candidate_scores_per_scenario"
        if not candidate_dir.exists():
            continue
        wrong = []
        for scenario in DEFAULT_SCENARIOS:
            path = candidate_dir / f"{scenario}_candidate_scores.csv"
            if not path.exists():
                continue
            expected_case = expected_source_case_id(scenario)
            for row in read_csv_dicts(path):
                if row.get("candidate_source") != "generated":
                    continue
                cases = split_multi(row.get("source_case_id", ""))
                if cases and expected_case not in cases:
                    wrong.append(f"{mode}:{scenario}:{row.get('playbook_id')}")
        add_check(
            rows,
            f"{mode}_no_cross_scenario_generated_candidates",
            allow_cross_scenario or not wrong,
            f"wrong={len(wrong)}",
        )


def main() -> None:
    args = parse_args()
    manifest = repo_path(args.manifest)
    generated_owl = repo_path(args.generated_owl)
    reduced_manifest = repo_path(args.reduced_manifest)
    evaluation_dir = repo_path(args.evaluation_dir)
    out_json = repo_path(args.out_json)
    out_csv = repo_path(args.out_csv)

    rows: list[dict[str, Any]] = []
    check_manifest(rows, manifest)
    check_owl_attack_coverage(rows, generated_owl)
    check_reduced_pool(rows, reduced_manifest, args.per_scenario)
    check_selection_outputs(rows, evaluation_dir, args.allow_cross_scenario_generated)

    passed = sum(1 for row in rows if row["passed"] == "True")
    failed = len(rows) - passed
    write_csv(out_csv, rows, ["check", "passed", "details"])
    write_json(out_json, {
        "artifact_status": "paper evaluation",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + " ".join(sys.argv),
        "evaluation_dir": repo_display_path(evaluation_dir),
        "manifest": repo_display_path(manifest),
        "manifest_sha256": file_sha256(manifest) if manifest.exists() else None,
        "generated_owl": repo_display_path(generated_owl),
        "generated_owl_sha256": (
            file_sha256(generated_owl) if generated_owl.exists() else None
        ),
        "passed": passed,
        "failed": failed,
        "checks": rows,
    })
    print(f"Sanity checks: {passed} passed, {failed} failed")
    print(f"Wrote {out_csv}")


if __name__ == "__main__":
    main()
