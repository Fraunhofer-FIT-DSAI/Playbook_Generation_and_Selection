#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import shlex
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from closed_loop_common import (
    DEFAULT_SCENARIOS,
    EVALUATION_MODES,
    GENERATED_REDUCED_MODES,
    canonical_mode,
    classify_playbook,
    coverage_by_playbook,
    execute_filtered_scenario_direct_attack_query,
    execute_filtered_scenario_query,
    execute_playbook_metadata_query,
    execute_scenario_universe_query,
    expected_source_case_id,
    expected_source_scenario_id,
    filter_rows,
    iter_scenario_paths,
    load_allowed_generated_ids,
    load_scenario_profile,
    local_name,
    metadata_by_playbook,
    playbook_sources,
    repo_display_path,
    repo_path,
    scenario_profile_cves,
    split_playbook_ids,
    technique_ids_from_sparql,
    to_float,
    value,
    write_csv,
    write_json,
)
from selection_protocol import (
    CLOSED_LOOP_BALANCED_WEIGHTS,
    COVERAGE_ONLY_WEIGHTS,
    CRITERIA,
    NEUTRAL_VALUE,
    TOP1_TIE_POLICY,
    protocol_manifest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run source-aware MCDM playbook selection."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path("selection_phase/source"),
        help="Selection-phase source inside this repository.",
    )
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=Path("data/scenario_profiles"),
        help="Scenario profile directory.",
    )
    parser.add_argument(
        "--endpoint",
        default="http://localhost:7200/repositories/incident-response",
        help="GraphDB repository SPARQL endpoint.",
    )
    parser.add_argument(
        "--mode",
        choices=EVALUATION_MODES,
        default="augmented-reduced",
        help="Candidate pool to evaluate.",
    )
    parser.add_argument(
        "--generated-prefix",
        default="ma_",
        help="Generated playbook ID prefix.",
    )
    parser.add_argument(
        "--reduced-manifest",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/"
            "reduced_generated_playbooks_manifest.csv"
        ),
        help="Reduced generated manifest used by generated-reduced and augmented-reduced modes.",
    )
    parser.add_argument(
        "--generated-owl",
        type=Path,
        help=(
            "Generated OWL loaded into GraphDB. For reduced modes, defaults to "
            "the sibling of --reduced-manifest with '_manifest.csv' replaced by '.owl'."
        ),
    )
    parser.add_argument(
        "--allow-cross-scenario-generated",
        action="store_true",
        help=(
            "Allow generated playbooks from other scenario-conditioned cases to compete. "
            "By default generated playbooks are restricted to the current scenario case."
        ),
    )
    parser.add_argument(
        "--scenario",
        action="append",
        help="Scenario name to evaluate. May be passed multiple times. Defaults to all canonical scenarios.",
    )
    parser.add_argument(
        "--defense-weight",
        type=float,
        default=0.5,
        help="Coverage-only defense coverage weight.",
    )
    parser.add_argument(
        "--artifact-weight",
        type=float,
        default=0.5,
        help="Coverage-only artifact coverage weight.",
    )
    parser.add_argument(
        "--scoring-profile",
        choices=[
            "coverage-only",
            "closed-loop-balanced",
            "coverage-primary",
            "coverage-constrained",
        ],
        default="coverage-only",
        help="MCDM scoring profile.",
    )
    parser.add_argument(
        "--coverage-threshold",
        type=float,
        default=0.9,
        help="Tau for coverage-constrained selection: require tau times the best single-candidate combined recall.",
    )
    parser.add_argument(
        "--disable-direct-attack-provenance",
        action="store_true",
        help="Ablation: ignore direct generated ATT&CK provenance during retrieval, scoring, and recall.",
    )
    parser.add_argument(
        "--disable-risk-criterion",
        action="store_true",
        help="Ablation: remove RC from closed-loop-balanced scoring.",
    )
    parser.add_argument(
        "--disable-cve-criterion",
        action="store_true",
        help="Ablation: remove CC from closed-loop-balanced scoring.",
    )
    parser.add_argument(
        "--missing-context-policy",
        choices=["neutral", "zero", "ignore"],
        default="neutral",
        help="How to score missing TC/RC/CC and other unavailable context criteria.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("results/evaluation/corrected"),
        help="Output directory.",
    )
    return parser.parse_args()


def file_sha256(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_all_playbooks(rows: list[dict[str, dict[str, str]]]) -> tuple[list[str], list[str]]:
    playbook_counter = Counter(value(row, "playbookID") for row in rows if value(row, "playbookID"))
    playbooks = sorted(playbook_counter)
    best_relevant = []
    if playbook_counter:
        max_count = max(playbook_counter.values())
        best_relevant = sorted(pb for pb, count in playbook_counter.items() if count == max_count)
    return playbooks, best_relevant


def get_defense_step_coverage(
    rows: list[dict[str, dict[str, str]]],
    universe_rows: list[dict[str, dict[str, str]]],
    scenario_attack_ids: set[str],
) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, float], dict[str, float]]:
    used_pairs: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    step_counts: dict[str, int] = defaultdict(int)
    redundancy: dict[str, int] = defaultdict(int)
    coverage: dict[str, int] = defaultdict(int)
    completeness: dict[str, float] = defaultdict(float)
    adjusted_completeness: dict[str, float] = defaultdict(float)
    defend_matrix: dict[str, set[str]] = defaultdict(set)

    for row in universe_rows:
        attack = local_name(value(row, "attackId"))
        rel_uri = value(row, "defenseRelationship")
        if not attack or "may-" not in rel_uri:
            continue
        defend_matrix[attack].add(local_name(rel_uri))

    for row in rows:
        playbook = value(row, "playbookID")
        step = value(row, "stepID")
        attack = local_name(value(row, "attackId"))
        rel_uri = value(row, "defenseRelationship")
        if not playbook or not step or "may-" not in rel_uri:
            continue
        rel = local_name(rel_uri)
        used_pairs[(playbook, attack, rel)].add(step)

    for (playbook, _attack, _rel), steps in used_pairs.items():
        count = len(steps)
        step_counts[playbook] += count
        coverage[playbook] += 1
        if count > 1:
            redundancy[playbook] += count - 1

    max_possible = sum(len(defend_matrix[attack]) for attack in scenario_attack_ids if attack in defend_matrix)

    for playbook in coverage:
        if max_possible > 0:
            completeness[playbook] = coverage[playbook] / max_possible
            penalty = redundancy[playbook] / step_counts[playbook] if step_counts[playbook] else 0
            adjusted_completeness[playbook] = completeness[playbook] * (1 - penalty)
        else:
            completeness[playbook] = 0
            adjusted_completeness[playbook] = 0

    return (
        dict(coverage),
        dict(step_counts),
        dict(redundancy),
        dict(completeness),
        dict(adjusted_completeness),
    )


def get_artifact_coverage_per_playbook(
    rows: list[dict[str, dict[str, str]]],
    universe_rows: list[dict[str, dict[str, str]]],
) -> tuple[dict[str, set[str]], set[str]]:
    artifact_coverage: dict[str, set[str]] = {}
    scenario_artifacts: set[str] = set()

    for row in universe_rows:
        artifact_uri = value(row, "artifact")
        if artifact_uri:
            scenario_artifacts.add(local_name(artifact_uri))

    for row in rows:
        playbook_id = value(row, "playbookID")
        artifact_uri = value(row, "artifact")
        if not playbook_id or not artifact_uri:
            continue
        artifact_coverage.setdefault(playbook_id, set()).add(local_name(artifact_uri))

    return artifact_coverage, scenario_artifacts


def serialize_score_dict(score_dict: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, item in score_dict.items():
        result[key] = sorted(item) if isinstance(item, set) else item
    return result


def metadata_set(metadata: dict[str, set[str] | str], key: str) -> set[str]:
    value_obj = metadata.get(key, set())
    return value_obj if isinstance(value_obj, set) else set()


def metadata_scalar(metadata: dict[str, set[str] | str], key: str) -> str:
    value_obj = metadata.get(key, "")
    return value_obj if isinstance(value_obj, str) else ""


def context_value(
    value_obj: float | None,
    field_name: str,
    missing_fields: list[str],
    policy: str,
) -> tuple[float, bool]:
    if value_obj is not None:
        return max(0.0, min(1.0, value_obj)), False
    missing_fields.append(field_name)
    if policy == "neutral":
        return NEUTRAL_VALUE, True
    if policy == "zero":
        return 0.0, True
    return 0.0, True


def ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def union_for_playbooks(coverage: dict[str, set[str]], playbooks: list[str]) -> set[str]:
    result: set[str] = set()
    for playbook in playbooks:
        result |= coverage.get(playbook, set())
    return result


def score_with_missing_policy(
    criteria: dict[str, float],
    missing_criteria: set[str],
    weights: dict[str, float],
    policy: str,
) -> float:
    if policy != "ignore":
        return sum(criteria.get(name, 0.0) * weight for name, weight in weights.items())
    active_weights = {
        name: weight for name, weight in weights.items() if name not in missing_criteria
    }
    total_weight = sum(active_weights.values())
    if total_weight <= 0:
        return 0.0
    return sum(criteria.get(name, 0.0) * weight for name, weight in active_weights.items()) / total_weight


def scoring_weights(args: argparse.Namespace) -> dict[str, float]:
    if args.scoring_profile == "coverage-only":
        return {"DC": args.defense_weight, "DAC": args.artifact_weight}

    weights = dict(CLOSED_LOOP_BALANCED_WEIGHTS)
    if args.disable_direct_attack_provenance:
        weights["DTC"] = 0.0
    if args.disable_risk_criterion:
        weights["RC"] = 0.0
    if args.disable_cve_criterion:
        weights["CC"] = 0.0

    total = sum(weights.values())
    if total <= 0:
        raise ValueError("At least one scoring criterion must retain a positive weight.")
    return {name: weight / total for name, weight in weights.items() if weight > 0}


def action_budget_scores(action_counts: dict[str, int | None]) -> dict[str, float | None]:
    available = [count for count in action_counts.values() if count is not None]
    if not available:
        return {playbook: None for playbook in action_counts}
    min_count = min(available)
    max_count = max(available)
    if min_count == max_count:
        return {playbook: (1.0 if count is not None else None) for playbook, count in action_counts.items()}
    return {
        playbook: (None if count is None else 1.0 - ((count - min_count) / (max_count - min_count)))
        for playbook, count in action_counts.items()
    }


def normalize_risk_scores(raw_values: dict[str, float | None]) -> dict[str, float | None]:
    max_value = max((value for value in raw_values.values() if value is not None), default=0.0)
    if max_value <= 0:
        return {playbook: (None if value is None else 0.0) for playbook, value in raw_values.items()}
    return {playbook: (None if value is None else value / max_value) for playbook, value in raw_values.items()}


def direct_metadata_for_playbooks(rows: list[dict[str, dict[str, str]]]) -> dict[str, dict[str, set[str] | str]]:
    return metadata_by_playbook(rows)


def candidate_float(row: dict[str, Any], key: str, default: float = 0.0) -> float:
    return to_float(row.get(key), default)


def candidate_int(row: dict[str, Any], key: str, default: int = 0) -> int:
    return int(to_float(row.get(key), float(default)))


def format_metric(value_obj: float) -> str:
    return f"{value_obj:.12f}"


def select_playbooks(
    scoring_profile: str,
    relevance_scores: dict[str, float],
    candidate_rows: list[dict[str, Any]],
    coverage_threshold: float,
) -> tuple[list[str], float, bool, float]:
    if not relevance_scores:
        return [], 0.0, False, 0.0

    by_id = {row["playbook_id"]: row for row in candidate_rows}
    oracle_combined_recall = max(
        candidate_float(row, "combined_attack_recall", 0.0)
        for row in candidate_rows
    ) if candidate_rows else 0.0

    if scoring_profile == "coverage-primary":
        ranked = sorted(
            relevance_scores,
            key=lambda playbook: (
                -candidate_float(by_id.get(playbook, {}), "combined_attack_recall", 0.0),
                -relevance_scores[playbook],
                candidate_int(by_id.get(playbook, {}), "action_count", 10**9),
                -candidate_float(by_id.get(playbook, {}), "raw_risk_reduction", 0.0),
                playbook,
            ),
        )
        top_playbook = ranked[0]
        return [top_playbook], relevance_scores[top_playbook], True, oracle_combined_recall

    if scoring_profile == "coverage-constrained":
        required = coverage_threshold * oracle_combined_recall
        retained = [
            playbook for playbook in relevance_scores
            if candidate_float(by_id.get(playbook, {}), "combined_attack_recall", 0.0) >= required - 1e-12
        ]
        threshold_satisfied = bool(retained)
        if not retained:
            retained = list(relevance_scores)
        ranked = sorted(
            retained,
            key=lambda playbook: (
                -relevance_scores[playbook],
                -candidate_float(by_id.get(playbook, {}), "combined_attack_recall", 0.0),
                candidate_int(by_id.get(playbook, {}), "action_count", 10**9),
                -candidate_float(by_id.get(playbook, {}), "raw_risk_reduction", 0.0),
                playbook,
            ),
        )
        top_playbook = ranked[0]
        return [top_playbook], relevance_scores[top_playbook], threshold_satisfied, oracle_combined_recall

    ranked = sorted(relevance_scores.items(), key=lambda item: item[1], reverse=True)
    max_score = ranked[0][1]
    tied = sorted(playbook for playbook, score in ranked if score == max_score)
    return [tied[0]], max_score, True, oracle_combined_recall


def main() -> None:
    args = parse_args()
    if args.scoring_profile == "coverage-only" and abs((args.defense_weight + args.artifact_weight) - 1.0) > 1e-9:
        raise ValueError("defense-weight and artifact-weight must sum to 1.0")

    project_root = repo_path(args.project_root)
    profile_dir = repo_path(args.profile_dir)
    mode = args.mode
    canonical = canonical_mode(mode)
    out_dir = repo_path(args.out_dir) / mode
    scores_dir = out_dir / "mcdm_scores_per_scenario"
    candidate_dir = out_dir / "candidate_scores_per_scenario"
    scores_dir.mkdir(parents=True, exist_ok=True)
    candidate_dir.mkdir(parents=True, exist_ok=True)

    reduced_manifest = repo_path(args.reduced_manifest)
    allowed_generated_ids = (
        load_allowed_generated_ids(reduced_manifest)
        if canonical in GENERATED_REDUCED_MODES
        else None
    )

    weights = scoring_weights(args)
    mapping_owl = repo_path(
        "selection_phase/source/GraphDB/playbook_step_defend_mapping.owl"
    )
    generated_owl = None
    if canonical in GENERATED_REDUCED_MODES:
        generated_owl = (
            repo_path(args.generated_owl)
            if args.generated_owl is not None
            else reduced_manifest.with_name(
                reduced_manifest.name.removesuffix("_manifest.csv") + ".owl"
            )
        )
        if generated_owl is None or not generated_owl.exists():
            raise FileNotFoundError(
                "Generated OWL for the reduced manifest was not found: "
                f"{generated_owl}"
            )
    run_started_at = datetime.now(timezone.utc).isoformat()

    all_results = []
    summary = {
        "result_state": "paper evaluation",
        "run_started_at_utc": run_started_at,
        "command": "python " + shlex.join(sys.argv),
        "mode": mode,
        "canonical_mode": canonical,
        "endpoint": args.endpoint,
        "generated_prefix": args.generated_prefix,
        "match_generated_source_case": not args.allow_cross_scenario_generated,
        "scoring_profile": args.scoring_profile,
        "missing_context_policy": args.missing_context_policy,
        "neutral_default": NEUTRAL_VALUE,
        "weights": weights,
        "top1_tie_policy": TOP1_TIE_POLICY,
        "selection_protocol": protocol_manifest(
            weights=weights,
            missing_context_policy=args.missing_context_policy,
        ),
        "risk_criterion_input": (
            "hasRelativeRiskReduction when present; legacy hasRiskReduction fallback"
        ),
        "reduced_manifest": (
            repo_display_path(reduced_manifest)
            if canonical in GENERATED_REDUCED_MODES
            else ""
        ),
        "reduced_manifest_sha256": (
            file_sha256(reduced_manifest)
            if canonical in GENERATED_REDUCED_MODES
            else ""
        ),
        "reduced_manifest_loaded": (
            bool(allowed_generated_ids)
            if canonical in GENERATED_REDUCED_MODES
            else False
        ),
        "mapping_owl": repo_display_path(mapping_owl),
        "mapping_owl_sha256": file_sha256(mapping_owl),
        "generated_owl": (
            repo_display_path(generated_owl)
            if canonical in GENERATED_REDUCED_MODES
            else ""
        ),
        "generated_owl_sha256": (
            file_sha256(generated_owl)
            if canonical in GENERATED_REDUCED_MODES
            else ""
        ),
        "historical_candidate_table_reused": False,
        "candidate_metadata_scope": "complete candidate ID set",
        "scenarios": {},
    }

    for scenario_name, sparql_path in iter_scenario_paths(project_root, args.scenario or DEFAULT_SCENARIOS):
        scenario_attack_ids = technique_ids_from_sparql(sparql_path)
        profile = load_scenario_profile(profile_dir, scenario_name)
        scenario_cves = scenario_profile_cves(profile)

        raw_inferred_rows = execute_filtered_scenario_query(
            args.endpoint,
            sparql_path,
            mode,
            args.generated_prefix,
            scenario_name=scenario_name,
            match_generated_source_case=not args.allow_cross_scenario_generated,
            allowed_generated_ids=allowed_generated_ids,
        )
        raw_direct_rows = execute_filtered_scenario_direct_attack_query(
            args.endpoint,
            sparql_path,
            mode,
            args.generated_prefix,
            scenario_name=scenario_name,
            match_generated_source_case=not args.allow_cross_scenario_generated,
            allowed_generated_ids=allowed_generated_ids,
        )
        if args.disable_direct_attack_provenance:
            raw_direct_rows = []
        universe_rows = execute_scenario_universe_query(args.endpoint, sparql_path)

        inferred_rows = filter_rows(
            raw_inferred_rows,
            mode,
            args.generated_prefix,
            scenario_name=scenario_name,
            match_generated_source_case=not args.allow_cross_scenario_generated,
            allowed_generated_ids=allowed_generated_ids,
        )
        direct_rows = filter_rows(
            raw_direct_rows,
            mode,
            args.generated_prefix,
            scenario_name=scenario_name,
            match_generated_source_case=not args.allow_cross_scenario_generated,
            allowed_generated_ids=allowed_generated_ids,
        )

        inferred_playbooks, _ = get_all_playbooks(inferred_rows)
        direct_playbooks, _ = get_all_playbooks(direct_rows)
        all_playbooks = sorted(set(inferred_playbooks) | set(direct_playbooks))

        if not all_playbooks:
            all_results.append({
                "Scenario": scenario_name,
                "Top_MCDM_Playbook": "",
                "Top_Playbook_Source": "",
                "MCDM_Score": "",
                "Artifact_Coverage": "",
                "Defense_Coverage": "",
                "Candidate_Count": 0,
                "Scenario_Attack_Count": len(scenario_attack_ids),
                "candidate_source": "",
                "DC": "",
                "DAC": "",
                "DTC": "",
                "TC": "",
                "RC": "",
                "CC": "",
                "AC": "",
                "total_score": "",
                "missing_context_fields": "",
                "scoring_profile": args.scoring_profile,
                "missing_context_policy": args.missing_context_policy,
                "coverage_threshold": format_metric(args.coverage_threshold),
                "coverage_threshold_satisfied": "",
                "oracle_combined_attack_recall": "",
                "selected_action_count": "",
                "selected_risk_reduction": "",
                "source_case_id": "",
                "source_scenario_id": "",
                "attack_path_id": "",
                "direct_attack_recall": "",
                "inferred_attack_recall": "",
                "combined_attack_recall": "",
                "achievable_attack_technique_count": "",
                "achievable_direct_attack_recall": "",
                "achievable_inferred_attack_recall": "",
                "achievable_combined_attack_recall": "",
                "normalized_direct_attack_recall": "",
                "normalized_inferred_attack_recall": "",
                "normalized_combined_attack_recall": "",
                "generated_candidate_count": 0,
                "community_candidate_count": 0,
                "reduced_generated_candidate_count": 0,
            })
            continue

        inferred_attack_coverage = coverage_by_playbook(inferred_rows, "attackId")
        direct_attack_coverage = coverage_by_playbook(direct_rows, "attackId")
        combined_attack_coverage = {
            playbook: inferred_attack_coverage.get(playbook, set()) | direct_attack_coverage.get(playbook, set())
            for playbook in all_playbooks
        }
        achievable_direct_attacks = union_for_playbooks(direct_attack_coverage, all_playbooks) & scenario_attack_ids
        achievable_inferred_attacks = union_for_playbooks(inferred_attack_coverage, all_playbooks) & scenario_attack_ids
        achievable_combined_attacks = union_for_playbooks(combined_attack_coverage, all_playbooks) & scenario_attack_ids
        achievable_direct_recall = (
            len(achievable_direct_attacks) / len(scenario_attack_ids)
            if scenario_attack_ids else 0.0
        )
        achievable_inferred_recall = (
            len(achievable_inferred_attacks) / len(scenario_attack_ids)
            if scenario_attack_ids else 0.0
        )
        achievable_combined_recall = (
            len(achievable_combined_attacks) / len(scenario_attack_ids)
            if scenario_attack_ids else 0.0
        )

        (
            unique_step_number,
            step_counts,
            redundancy,
            completeness,
            defend_coverage,
        ) = get_defense_step_coverage(inferred_rows, universe_rows, scenario_attack_ids)

        artifact_mappings, scenario_artifacts = get_artifact_coverage_per_playbook(inferred_rows, universe_rows)
        artifact_coverage = {
            playbook: len(artifact_mappings.get(playbook, set())) / len(scenario_artifacts)
            for playbook in all_playbooks
            if scenario_artifacts
        }

        metadata_rows = execute_playbook_metadata_query(args.endpoint, all_playbooks)
        metadata = direct_metadata_for_playbooks(metadata_rows)
        raw_risk_reduction: dict[str, float | None] = {}
        action_counts: dict[str, int | None] = {}
        for playbook in all_playbooks:
            item = metadata.get(playbook, {})
            raw_risk = metadata_scalar(item, "risk_reduction")
            raw_risk_reduction[playbook] = to_float(raw_risk, None) if raw_risk else None
            raw_action_count = metadata_scalar(item, "action_count")
            if raw_action_count:
                action_counts[playbook] = int(to_float(raw_action_count, 0))
            elif metadata_set(item, "steps"):
                action_counts[playbook] = len(metadata_set(item, "steps"))
            elif step_counts.get(playbook):
                action_counts[playbook] = step_counts[playbook]
            else:
                direct_step_ids = {
                    value(row, "stepID")
                    for row in direct_rows
                    if value(row, "playbookID") == playbook and value(row, "stepID")
                }
                action_counts[playbook] = len(direct_step_ids) if direct_step_ids else None

        risk_scores = normalize_risk_scores(raw_risk_reduction)
        action_scores = action_budget_scores(action_counts)
        expected_case = expected_source_case_id(scenario_name)
        expected_scenario = expected_source_scenario_id(scenario_name)

        candidate_rows = []
        relevance_scores = {}
        missing_by_playbook: dict[str, list[str]] = {}

        for playbook in all_playbooks:
            source = classify_playbook(playbook, args.generated_prefix)
            item = metadata.get(playbook, {})
            missing_fields: list[str] = []
            missing_criteria: set[str] = set()

            dc = defend_coverage.get(playbook, 0.0)
            dac = artifact_coverage.get(playbook, 0.0)
            dtc = (
                len(direct_attack_coverage.get(playbook, set()) & scenario_attack_ids) / len(scenario_attack_ids)
                if scenario_attack_ids else 0.0
            )

            source_cases = metadata_set(item, "source_cases")
            source_scenarios = metadata_set(item, "source_scenarios")
            attack_paths = metadata_set(item, "attack_paths")
            target_hosts = metadata_set(item, "target_hosts")
            cves = metadata_set(item, "cves")

            tc_raw: float | None
            if source == "generated":
                if expected_case in source_cases or expected_scenario in source_scenarios:
                    tc_raw = 1.0
                elif source_cases or source_scenarios:
                    tc_raw = 0.0
                else:
                    tc_raw = None
            else:
                tc_raw = None
            tc, missing_tc = context_value(tc_raw, "TC", missing_fields, args.missing_context_policy)
            if missing_tc:
                missing_criteria.add("TC")

            rc, missing_rc = context_value(risk_scores.get(playbook), "RC", missing_fields, args.missing_context_policy)
            if missing_rc:
                missing_criteria.add("RC")

            if scenario_cves:
                cc_raw = len(cves & scenario_cves) / len(scenario_cves) if cves else None
            else:
                cc_raw = None
            cc, missing_cc = context_value(cc_raw, "CC", missing_fields, args.missing_context_policy)
            if missing_cc:
                missing_criteria.add("CC")

            ac, missing_ac = context_value(action_scores.get(playbook), "AC", missing_fields, args.missing_context_policy)
            if missing_ac:
                missing_criteria.add("AC")

            if source == "generated" and not direct_attack_coverage.get(playbook):
                missing_fields.append("direct_ATTCK_provenance")
            if source == "generated" and not target_hosts:
                missing_fields.append("topology_metadata")

            criteria = {
                "DC": dc,
                "DAC": dac,
                "DTC": dtc,
                "TC": tc,
                "RC": rc,
                "CC": cc,
                "AC": ac,
            }
            total_score = score_with_missing_policy(
                criteria,
                missing_criteria,
                weights,
                args.missing_context_policy,
            )
            relevance_scores[playbook] = total_score
            missing_by_playbook[playbook] = missing_fields

            inferred_recall = (
                len(inferred_attack_coverage.get(playbook, set()) & scenario_attack_ids) / len(scenario_attack_ids)
                if scenario_attack_ids else 0.0
            )
            direct_recall = dtc
            combined_recall = (
                len(combined_attack_coverage.get(playbook, set()) & scenario_attack_ids) / len(scenario_attack_ids)
                if scenario_attack_ids else 0.0
            )
            normalized_direct_recall = ratio(
                len(direct_attack_coverage.get(playbook, set()) & scenario_attack_ids),
                len(achievable_direct_attacks),
            )
            normalized_inferred_recall = ratio(
                len(inferred_attack_coverage.get(playbook, set()) & scenario_attack_ids),
                len(achievable_inferred_attacks),
            )
            normalized_combined_recall = ratio(
                len(combined_attack_coverage.get(playbook, set()) & scenario_attack_ids),
                len(achievable_combined_attacks),
            )

            candidate_rows.append({
                "Scenario": scenario_name,
                "playbook_id": playbook,
                "candidate_source": source,
                "DC": format_metric(dc),
                "DAC": format_metric(dac),
                "DTC": format_metric(dtc),
                "TC": format_metric(tc),
                "RC": format_metric(rc),
                "CC": format_metric(cc),
                "AC": format_metric(ac),
                "total_score": format_metric(total_score),
                "direct_attack_recall": format_metric(direct_recall),
                "inferred_attack_recall": format_metric(inferred_recall),
                "combined_attack_recall": format_metric(combined_recall),
                "normalized_direct_attack_recall": format_metric(normalized_direct_recall),
                "normalized_inferred_attack_recall": format_metric(normalized_inferred_recall),
                "normalized_combined_attack_recall": format_metric(normalized_combined_recall),
                "achievable_combined_attack_recall": format_metric(achievable_combined_recall),
                "raw_risk_reduction": (
                    ""
                    if raw_risk_reduction.get(playbook) is None
                    else format_metric(raw_risk_reduction[playbook])
                ),
                "action_count": "" if action_counts.get(playbook) is None else action_counts[playbook],
                "source_case_id": ";".join(sorted(source_cases)),
                "source_scenario_id": ";".join(sorted(source_scenarios)),
                "attack_path_id": ";".join(sorted(attack_paths)),
                "covered_cves": ";".join(sorted(cves)),
                "target_hosts": ";".join(sorted(target_hosts)),
                "missing_context_fields": ";".join(sorted(set(missing_fields))),
                "scoring_profile": args.scoring_profile,
                "missing_context_policy": args.missing_context_policy,
                "coverage_threshold": format_metric(args.coverage_threshold),
                "coverage_threshold_satisfied": "",
                "oracle_combined_attack_recall": "",
            })

        write_json(scores_dir / f"{scenario_name}_mcdm_scores.json", relevance_scores)
        write_json(scores_dir / f"{scenario_name}_defense_coverage.json", defend_coverage)
        write_json(scores_dir / f"{scenario_name}_artifact_coverage.json", artifact_coverage)
        write_json(scores_dir / f"{scenario_name}_direct_attack_coverage.json", serialize_score_dict(direct_attack_coverage))
        write_json(scores_dir / f"{scenario_name}_inferred_attack_coverage.json", serialize_score_dict(inferred_attack_coverage))
        write_json(scores_dir / f"{scenario_name}_combined_attack_coverage.json", serialize_score_dict(combined_attack_coverage))
        write_json(scores_dir / f"{scenario_name}_step_counts.json", step_counts)
        write_json(scores_dir / f"{scenario_name}_redundancy.json", redundancy)
        write_json(scores_dir / f"{scenario_name}_raw_completeness.json", completeness)
        write_json(scores_dir / f"{scenario_name}_unique_step_number.json", unique_step_number)

        candidate_fieldnames = [
            "Scenario",
            "playbook_id",
            "candidate_source",
            "DC",
            "DAC",
            "DTC",
            "TC",
            "RC",
            "CC",
            "AC",
            "total_score",
            "direct_attack_recall",
            "inferred_attack_recall",
            "combined_attack_recall",
            "normalized_direct_attack_recall",
            "normalized_inferred_attack_recall",
            "normalized_combined_attack_recall",
            "achievable_combined_attack_recall",
            "raw_risk_reduction",
            "action_count",
            "source_case_id",
            "source_scenario_id",
            "attack_path_id",
            "covered_cves",
            "target_hosts",
            "missing_context_fields",
            "scoring_profile",
            "missing_context_policy",
            "coverage_threshold",
            "coverage_threshold_satisfied",
            "oracle_combined_attack_recall",
        ]
        write_csv(candidate_dir / f"{scenario_name}_candidate_scores.csv", candidate_rows, candidate_fieldnames)

        top_playbooks, max_score, coverage_threshold_satisfied, oracle_combined_recall = select_playbooks(
            args.scoring_profile,
            relevance_scores,
            candidate_rows,
            args.coverage_threshold,
        )
        top_playbook = top_playbooks[0]
        top_source = classify_playbook(top_playbook, args.generated_prefix)
        defense_cov = defend_coverage.get(top_playbook, 0)
        artifact_cov = artifact_coverage.get(top_playbook, 0)
        selected_direct_attacks = union_for_playbooks(direct_attack_coverage, top_playbooks) & scenario_attack_ids
        selected_inferred_attacks = union_for_playbooks(inferred_attack_coverage, top_playbooks) & scenario_attack_ids
        selected_combined_attacks = selected_direct_attacks | selected_inferred_attacks
        direct_recall = (
            len(selected_direct_attacks) / len(scenario_attack_ids)
            if scenario_attack_ids else 0.0
        )
        inferred_recall = (
            len(selected_inferred_attacks) / len(scenario_attack_ids)
            if scenario_attack_ids else 0.0
        )
        combined_recall = (
            len(selected_combined_attacks) / len(scenario_attack_ids)
            if scenario_attack_ids else 0.0
        )
        normalized_direct_recall = ratio(len(selected_direct_attacks), len(achievable_direct_attacks))
        normalized_inferred_recall = ratio(len(selected_inferred_attacks), len(achievable_inferred_attacks))
        normalized_combined_recall = ratio(len(selected_combined_attacks), len(achievable_combined_attacks))
        selected_candidate = next(row for row in candidate_rows if row["playbook_id"] == top_playbook)
        for row in candidate_rows:
            row["coverage_threshold_satisfied"] = str(
                candidate_float(row, "combined_attack_recall", 0.0)
                >= args.coverage_threshold * oracle_combined_recall - 1e-12
            )
            row["oracle_combined_attack_recall"] = format_metric(
                oracle_combined_recall
            )
        write_csv(candidate_dir / f"{scenario_name}_candidate_scores.csv", candidate_rows, candidate_fieldnames)
        generated_candidate_count = sum(1 for playbook in all_playbooks if classify_playbook(playbook, args.generated_prefix) == "generated")
        community_candidate_count = len(all_playbooks) - generated_candidate_count

        all_results.append({
            "Scenario": scenario_name,
            "Top_MCDM_Playbook": ", ".join(top_playbooks),
            "Top_Playbook_Source": playbook_sources(split_playbook_ids(", ".join(top_playbooks)), args.generated_prefix),
            "MCDM_Score": f"{max_score * 100:.2f}%",
            "Artifact_Coverage": f"{artifact_cov * 100:.2f}%",
            "Defense_Coverage": f"{defense_cov * 100:.2f}%",
            "Candidate_Count": len(all_playbooks),
            "Scenario_Attack_Count": len(scenario_attack_ids),
            "candidate_source": top_source,
            "DC": selected_candidate["DC"],
            "DAC": selected_candidate["DAC"],
            "DTC": selected_candidate["DTC"],
            "TC": selected_candidate["TC"],
            "RC": selected_candidate["RC"],
            "CC": selected_candidate["CC"],
            "AC": selected_candidate["AC"],
            "total_score": selected_candidate["total_score"],
            "missing_context_fields": selected_candidate["missing_context_fields"],
            "scoring_profile": args.scoring_profile,
            "missing_context_policy": args.missing_context_policy,
            "coverage_threshold": format_metric(args.coverage_threshold),
            "coverage_threshold_satisfied": str(coverage_threshold_satisfied),
            "oracle_combined_attack_recall": format_metric(oracle_combined_recall),
            "selected_action_count": selected_candidate.get("action_count", ""),
            "selected_risk_reduction": selected_candidate.get("raw_risk_reduction", ""),
            "source_case_id": selected_candidate.get("source_case_id", ""),
            "source_scenario_id": selected_candidate.get("source_scenario_id", ""),
            "attack_path_id": selected_candidate.get("attack_path_id", ""),
            "direct_attack_recall": format_metric(direct_recall),
            "inferred_attack_recall": format_metric(inferred_recall),
            "combined_attack_recall": format_metric(combined_recall),
            "achievable_attack_technique_count": len(achievable_combined_attacks),
            "achievable_direct_attack_recall": format_metric(achievable_direct_recall),
            "achievable_inferred_attack_recall": format_metric(achievable_inferred_recall),
            "achievable_combined_attack_recall": format_metric(achievable_combined_recall),
            "normalized_direct_attack_recall": format_metric(normalized_direct_recall),
            "normalized_inferred_attack_recall": format_metric(normalized_inferred_recall),
            "normalized_combined_attack_recall": format_metric(normalized_combined_recall),
            "generated_candidate_count": generated_candidate_count,
            "community_candidate_count": community_candidate_count,
            "reduced_generated_candidate_count": generated_candidate_count if canonical in GENERATED_REDUCED_MODES else "",
        })

        summary["scenarios"][scenario_name] = {
            "candidate_count": len(all_playbooks),
            "generated_candidate_count": generated_candidate_count,
            "community_candidate_count": community_candidate_count,
            "scenario_attack_count": len(scenario_attack_ids),
            "achievable_attack_technique_count": len(achievable_combined_attacks),
            "achievable_combined_attack_recall": achievable_combined_recall,
            "normalized_combined_attack_recall": normalized_combined_recall,
            "top_playbooks": top_playbooks,
            "top_score": max_score,
            "top_source": top_source,
            "top_missing_context_fields": missing_by_playbook.get(top_playbook, []),
        }

    numeric_scores = []
    for row in all_results:
        score_text = row.get("MCDM_Score", "")
        if score_text:
            numeric_scores.append(float(score_text.rstrip("%")))
    if numeric_scores:
        all_results.append({
            "Scenario": "Average",
            "Top_MCDM_Playbook": "",
            "Top_Playbook_Source": "",
            "MCDM_Score": f"{sum(numeric_scores) / len(numeric_scores):.2f}%",
            "Artifact_Coverage": "",
            "Defense_Coverage": "",
            "Candidate_Count": "",
            "Scenario_Attack_Count": "",
            "candidate_source": "",
            "DC": "",
            "DAC": "",
            "DTC": "",
            "TC": "",
            "RC": "",
            "CC": "",
            "AC": "",
            "total_score": "",
            "missing_context_fields": "",
            "scoring_profile": args.scoring_profile,
            "missing_context_policy": args.missing_context_policy,
            "coverage_threshold": format_metric(args.coverage_threshold),
            "coverage_threshold_satisfied": "",
            "oracle_combined_attack_recall": "",
            "selected_action_count": "",
            "selected_risk_reduction": "",
            "source_case_id": "",
            "source_scenario_id": "",
            "attack_path_id": "",
            "direct_attack_recall": "",
            "inferred_attack_recall": "",
            "combined_attack_recall": "",
            "achievable_attack_technique_count": "",
            "achievable_direct_attack_recall": "",
            "achievable_inferred_attack_recall": "",
            "achievable_combined_attack_recall": "",
            "normalized_direct_attack_recall": "",
            "normalized_inferred_attack_recall": "",
            "normalized_combined_attack_recall": "",
            "generated_candidate_count": "",
            "community_candidate_count": "",
            "reduced_generated_candidate_count": "",
        })

    csv_path = out_dir / f"scenario_playbook_evaluation_{mode}.csv"
    write_csv(
        csv_path,
        all_results,
        [
            "Scenario",
            "Top_MCDM_Playbook",
            "Top_Playbook_Source",
            "MCDM_Score",
            "Artifact_Coverage",
            "Defense_Coverage",
            "Candidate_Count",
            "Scenario_Attack_Count",
            "candidate_source",
            "DC",
            "DAC",
            "DTC",
            "TC",
            "RC",
            "CC",
            "AC",
            "total_score",
            "missing_context_fields",
            "scoring_profile",
            "missing_context_policy",
            "coverage_threshold",
            "coverage_threshold_satisfied",
            "oracle_combined_attack_recall",
            "selected_action_count",
            "selected_risk_reduction",
            "source_case_id",
            "source_scenario_id",
            "attack_path_id",
            "direct_attack_recall",
            "inferred_attack_recall",
            "combined_attack_recall",
            "achievable_attack_technique_count",
            "achievable_direct_attack_recall",
            "achievable_inferred_attack_recall",
            "achievable_combined_attack_recall",
            "normalized_direct_attack_recall",
            "normalized_inferred_attack_recall",
            "normalized_combined_attack_recall",
            "generated_candidate_count",
            "community_candidate_count",
            "reduced_generated_candidate_count",
        ],
    )
    summary["run_completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    summary["scenario_count"] = len(summary["scenarios"])
    summary["selection_csv"] = repo_display_path(csv_path)
    summary["selection_csv_sha256"] = file_sha256(csv_path)
    write_json(out_dir / "selection_summary.json", summary)
    print(f"Wrote selection results to {csv_path}")


if __name__ == "__main__":
    main()
