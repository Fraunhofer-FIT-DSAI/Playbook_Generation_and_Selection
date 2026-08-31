#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

try:
    from rdflib import Graph, Literal, Namespace, URIRef
    from rdflib.namespace import RDF, XSD
except ModuleNotFoundError:
    Graph = Literal = Namespace = URIRef = RDF = XSD = None

from closed_loop_common import join_multi, read_jsonl, repo_path, safe_id, write_csv


IRSO = Namespace("http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#") if Namespace else None
D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#") if Namespace else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert exported generated playbooks to the repository ontology shape."
    )
    parser.add_argument(
        "--input-jsonl",
        type=Path,
        default=Path("results/generated_repository/export/generated_playbooks.jsonl"),
        help="Input JSONL produced by export_generated_playbooks.py.",
    )
    parser.add_argument(
        "--output-owl",
        type=Path,
        default=Path("results/generated_repository/generated_playbooks.owl"),
        help="Output RDF/XML OWL file.",
    )
    parser.add_argument(
        "--manifest-csv",
        type=Path,
        default=Path("results/generated_repository/generated_playbooks_manifest.csv"),
        help="CSV manifest for the generated ontology entries.",
    )
    return parser.parse_args()


def require_rdflib() -> None:
    if Graph is None:
        raise RuntimeError("Missing dependency: rdflib. Install dependencies with `pip install -r requirements.txt`.")


def literal(value: object) -> Literal:
    return Literal("" if value is None else str(value), datatype=XSD.string)


def values(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    return [item.strip() for item in text.split(";") if item.strip()]


def step_attack_ids(step: dict) -> list[str]:
    attacks = set(values(step.get("attack_techniques", [])))
    attack_technique_id = step.get("attack_technique_id", "")
    if attack_technique_id:
        attacks.add(str(attack_technique_id).strip())
    return sorted(attack for attack in attacks if attack)


def covered_attack_ids_from_steps(steps: list[dict]) -> list[str]:
    attacks = set()
    for step in steps:
        attacks.update(step_attack_ids(step))
    return sorted(attacks)


def add_literal_if_present(graph: Graph, subject: URIRef, predicate: URIRef, value: object) -> None:
    if value is None or value == "" or value == [] or value == {}:
        return
    graph.add((subject, predicate, literal(value)))


def add_float_if_present(graph: Graph, subject: URIRef, predicate: URIRef, value: object) -> None:
    try:
        graph.add((subject, predicate, Literal(float(value))))
    except (TypeError, ValueError):
        return


def add_int_if_present(graph: Graph, subject: URIRef, predicate: URIRef, value: object) -> None:
    try:
        graph.add((subject, predicate, Literal(int(value))))
    except (TypeError, ValueError):
        return


def enriched_playbook(playbook: dict) -> dict:
    steps = playbook.get("steps", [])
    incident = playbook.get("incident", [])
    if not playbook.get("source"):
        playbook["source"] = "generated"
    if not playbook.get("source_case_id"):
        playbook["source_case_id"] = playbook.get("source_case", "")
    if not playbook.get("source_scenario_id") and str(playbook.get("source_case_id", "")).startswith("scenario_"):
        playbook["source_scenario_id"] = str(playbook["source_case_id"]).removeprefix("scenario_")
    if not playbook.get("scenario_name") and playbook.get("source_scenario_id"):
        playbook["scenario_name"] = str(playbook["source_scenario_id"]).replace("_", " ")
    if not playbook.get("risk_before"):
        playbook["risk_before"] = playbook.get("initial_risk", "")
    if not playbook.get("risk_after"):
        playbook["risk_after"] = playbook.get("final_risk", "")
    if not playbook.get("risk_reduction"):
        try:
            playbook["risk_reduction"] = max(float(playbook.get("risk_before") or 0.0) - float(playbook.get("risk_after") or 0.0), 0.0)
        except (TypeError, ValueError):
            playbook["risk_reduction"] = ""
    if playbook.get("risk_reduction_pct") in {None, ""}:
        try:
            risk_before = float(playbook.get("risk_before") or 0.0)
            playbook["risk_reduction_pct"] = (
                max(risk_before - float(playbook.get("risk_after") or 0.0), 0.0)
                / risk_before
                if risk_before > 0
                else 0.0
            )
        except (TypeError, ValueError):
            playbook["risk_reduction_pct"] = ""
    if not playbook.get("attack_techniques"):
        attacks = {step.get("attack_technique_id", "") for step in steps if step.get("attack_technique_id", "")}
        for item in incident:
            mitre = str(item.get("mitre", ""))
            if "T" in mitre:
                attacks.add(mitre.split()[-1])
        playbook["attack_techniques"] = sorted(attacks)
    if not playbook.get("cves"):
        playbook["cves"] = sorted({item.get("cve", "") for item in incident if item.get("cve", "")} | {step.get("cve", "") for step in steps if step.get("cve", "")})
    if not playbook.get("cvss_scores"):
        playbook["cvss_scores"] = sorted({str(item.get("cvss", "")) for item in incident if str(item.get("cvss", "")).strip()} | {str(step.get("cvss_score", "")) for step in steps if str(step.get("cvss_score", "")).strip()})
    if not playbook.get("d3fend_techniques"):
        playbook["d3fend_techniques"] = sorted({step.get("defensive_technique_id", "") for step in steps if step.get("defensive_technique_id", "")})
    if not playbook.get("digital_artifacts"):
        playbook["digital_artifacts"] = sorted({step.get("defense_artifact_id", "") for step in steps if step.get("defense_artifact_id", "")})
    if not playbook.get("affected_hosts"):
        playbook["affected_hosts"] = sorted({item.get("host", "") for item in incident if item.get("host", "")} | {step.get("host", "") for step in steps if step.get("host", "")})
    if not playbook.get("lifecycle_phases_present"):
        playbook["lifecycle_phases_present"] = sorted({step.get("phase", "") for step in steps if step.get("phase", "")})
    if playbook.get("phase_completeness") in {None, ""}:
        phase_count = len({step.get("phase", "") for step in steps if step.get("phase", "")})
        playbook["phase_completeness"] = phase_count / 4 if phase_count else ""
    if not playbook.get("action_count"):
        playbook["action_count"] = len(steps)
    if not playbook.get("path_length"):
        playbook["path_length"] = len(incident)
    return playbook


def main() -> None:
    args = parse_args()
    require_rdflib()
    input_jsonl = repo_path(args.input_jsonl)
    output_owl = repo_path(args.output_owl)
    manifest_csv = repo_path(args.manifest_csv)
    playbooks = read_jsonl(input_jsonl)

    graph = Graph()
    graph.bind("irso", IRSO)
    graph.bind("d3f", D3F)

    manifest_rows = []

    for playbook in playbooks:
        playbook = enriched_playbook(playbook)
        playbook_id = playbook["playbook_id"]
        playbook_uri = URIRef(IRSO + "Playbook_" + safe_id(playbook_id))
        graph.add((playbook_uri, RDF.type, IRSO.Playbook))
        graph.add((playbook_uri, IRSO.hasPlaybookID, literal(playbook_id)))
        graph.add((playbook_uri, IRSO.hasPlaybookName, literal(playbook["playbook_name"])))
        graph.add((playbook_uri, IRSO.hasPlaybookDescription, literal(playbook.get("description", ""))))
        graph.add((playbook_uri, IRSO.source, literal(playbook.get("source", "generated"))))
        graph.add((playbook_uri, IRSO.generatedFromSource, literal("attack-graph-generation")))
        graph.add((playbook_uri, IRSO.generatedFromCase, literal(playbook.get("source_case", ""))))
        graph.add((playbook_uri, IRSO.sourceCaseId, literal(playbook.get("source_case_id", playbook.get("source_case", "")))))
        add_literal_if_present(graph, playbook_uri, IRSO.sourceScenarioId, playbook.get("source_scenario_id", ""))
        add_literal_if_present(graph, playbook_uri, IRSO.scenarioName, playbook.get("scenario_name", ""))
        add_literal_if_present(graph, playbook_uri, IRSO.derivedFromAttackPath, playbook.get("attack_path_id", ""))
        add_literal_if_present(graph, playbook_uri, IRSO.derivedFromScenario, playbook.get("source_scenario_id", ""))
        add_literal_if_present(graph, playbook_uri, IRSO.attackerStart, playbook.get("attacker_start", ""))
        add_literal_if_present(graph, playbook_uri, IRSO.attackerGoal, playbook.get("attacker_goal", ""))
        graph.add((playbook_uri, IRSO.generatedFromIncidentIndex, Literal(int(playbook.get("incident_index", 0)))))
        graph.add((playbook_uri, IRSO.hasInitialRisk, Literal(float(playbook.get("initial_risk", 0.0)))))
        graph.add((playbook_uri, IRSO.hasFinalRisk, Literal(float(playbook.get("final_risk", 0.0)))))
        add_float_if_present(graph, playbook_uri, IRSO.hasRiskBefore, playbook.get("risk_before", playbook.get("initial_risk", "")))
        add_float_if_present(graph, playbook_uri, IRSO.hasRiskAfter, playbook.get("risk_after", playbook.get("final_risk", "")))
        add_float_if_present(graph, playbook_uri, IRSO.hasRiskReduction, playbook.get("risk_reduction", ""))
        add_float_if_present(
            graph,
            playbook_uri,
            IRSO.hasRelativeRiskReduction,
            playbook.get("risk_reduction_pct", ""),
        )
        add_int_if_present(graph, playbook_uri, IRSO.pathLength, playbook.get("path_length", ""))
        add_int_if_present(graph, playbook_uri, IRSO.actionCount, playbook.get("action_count", ""))
        add_float_if_present(graph, playbook_uri, IRSO.phaseCompleteness, playbook.get("phase_completeness", ""))
        add_literal_if_present(graph, playbook_uri, IRSO.hostBindings, playbook.get("host_bindings", ""))

        for cve in values(playbook.get("cves", [])):
            graph.add((playbook_uri, IRSO.addressesCVE, literal(cve)))
        for host in values(playbook.get("affected_hosts", [])):
            graph.add((playbook_uri, IRSO.targetsHost, literal(host)))
        for phase in values(playbook.get("lifecycle_phases_present", [])):
            graph.add((playbook_uri, IRSO.hasLifecyclePhase, literal(phase)))
        for artifact_id in values(playbook.get("digital_artifacts", [])):
            graph.add((playbook_uri, IRSO.affects, URIRef(D3F + safe_id(artifact_id))))
        for defensive_id in values(playbook.get("d3fend_techniques", [])):
            graph.add((playbook_uri, IRSO.usesDefensiveTechnique, URIRef(D3F + safe_id(defensive_id))))
        covered_attack_ids = covered_attack_ids_from_steps(playbook["steps"])
        for attack_id in values(playbook.get("attack_techniques", [])):
            graph.add((playbook_uri, IRSO.sourceAttackTechnique, URIRef(D3F + safe_id(attack_id))))
        for attack_id in covered_attack_ids:
            attack_uri = URIRef(D3F + safe_id(attack_id))
            graph.add((playbook_uri, IRSO.coversAttackTechnique, attack_uri))
            graph.add((playbook_uri, IRSO.generatedForAttackTechnique, attack_uri))

        for step in playbook["steps"]:
            step_id = step["step_id"]
            step_uri = URIRef(IRSO + "Step_" + safe_id(step_id))
            graph.add((step_uri, RDF.type, IRSO.Step))
            graph.add((step_uri, IRSO.hasStepID, literal(step_id)))
            graph.add((step_uri, IRSO.hasStepName, literal(step["step_name"])))
            graph.add((step_uri, IRSO.hasStepDescription, literal(step["step_description"])))
            graph.add((step_uri, IRSO.hasResponsePhase, literal(step.get("phase", ""))))
            graph.add((step_uri, IRSO.hasRiskReduction, Literal(float(step.get("risk_reduction", 0.0)))))
            graph.add((step_uri, IRSO.source, literal(step.get("source", "generated"))))
            graph.add((step_uri, IRSO.sourceCaseId, literal(step.get("source_case_id", playbook.get("source_case_id", "")))))
            add_literal_if_present(graph, step_uri, IRSO.sourceScenarioId, step.get("source_scenario_id", playbook.get("source_scenario_id", "")))
            add_literal_if_present(graph, step_uri, IRSO.derivedFromAttackPath, step.get("attack_path_id", playbook.get("attack_path_id", "")))
            add_literal_if_present(graph, step_uri, IRSO.hasCommandText, step.get("command", ""))
            add_literal_if_present(graph, step_uri, IRSO.targetsHost, step.get("host_binding", step.get("host", "")))
            add_literal_if_present(graph, step_uri, IRSO.addressesCVE, step.get("cve", ""))
            graph.add((playbook_uri, IRSO.hasStep, step_uri))

            defensive_id = step.get("defensive_technique_id", "")
            if defensive_id:
                graph.add((step_uri, IRSO.usesDefensiveTechnique, URIRef(D3F + safe_id(defensive_id))))

            defense_artifact_id = step.get("defense_artifact_id", "")
            if defense_artifact_id:
                graph.add((step_uri, IRSO.affects, URIRef(D3F + safe_id(defense_artifact_id))))

            attack_technique_id = step.get("attack_technique_id", "")
            for step_attack_id in step_attack_ids(step):
                graph.add((step_uri, IRSO.generatedForAttackTechnique, URIRef(D3F + safe_id(step_attack_id))))
            matched_attack_id = step.get("matched_attack_technique_id", "")
            if matched_attack_id:
                graph.add((
                    step_uri,
                    IRSO.matchedMappingAttackTechnique,
                    URIRef(D3F + safe_id(matched_attack_id)),
                ))

            manifest_rows.append({
                "playbook_id": playbook_id,
                "source": playbook.get("source", "generated"),
                "source_case": playbook.get("source_case", ""),
                "source_case_id": playbook.get("source_case_id", playbook.get("source_case", "")),
                "source_scenario_id": playbook.get("source_scenario_id", ""),
                "scenario_name": playbook.get("scenario_name", ""),
                "attack_path_id": playbook.get("attack_path_id", ""),
                "attacker_start": playbook.get("attacker_start", ""),
                "attacker_goal": playbook.get("attacker_goal", ""),
                "incident_index": playbook.get("incident_index", ""),
                "playbook_cves": join_multi(playbook.get("cves", [])),
                "playbook_cvss_scores": join_multi(playbook.get("cvss_scores", [])),
                "playbook_cvss_severities": join_multi(playbook.get("cvss_severities", [])),
                "playbook_attack_techniques": join_multi(playbook.get("attack_techniques", [])),
                "playbook_covered_attack_techniques": join_multi(covered_attack_ids),
                "playbook_d3fend_techniques": join_multi(playbook.get("d3fend_techniques", [])),
                "playbook_digital_artifacts": join_multi(playbook.get("digital_artifacts", [])),
                "affected_hosts": join_multi(playbook.get("affected_hosts", [])),
                "host_bindings": playbook.get("host_bindings", {}),
                "risk_before": playbook.get("risk_before", playbook.get("initial_risk", "")),
                "risk_after": playbook.get("risk_after", playbook.get("final_risk", "")),
                "playbook_risk_reduction": playbook.get("risk_reduction", ""),
                "playbook_risk_reduction_pct": playbook.get("risk_reduction_pct", ""),
                "path_length": playbook.get("path_length", ""),
                "action_count": playbook.get("action_count", ""),
                "lifecycle_phases_present": join_multi(playbook.get("lifecycle_phases_present", [])),
                "phase_completeness": playbook.get("phase_completeness", ""),
                "step_id": step_id,
                "phase": step.get("phase", ""),
                "host_binding": step.get("host_binding", step.get("host", "")),
                "cve": step.get("cve", ""),
                "cvss_score": step.get("cvss_score", ""),
                "cvss_severity": step.get("cvss_severity", ""),
                "defensive_technique_id": defensive_id,
                "defensive_technique_label": step.get("defensive_technique_label", ""),
                "defense_artifact_id": defense_artifact_id,
                "attack_technique_id": attack_technique_id,
                "matched_attack_technique_id": matched_attack_id,
                "attack_techniques": join_multi(step.get("attack_techniques", [attack_technique_id] if attack_technique_id else [])),
                "attack_technique_label": step.get("attack_technique_label", ""),
                "command": step.get("command", ""),
                "risk_reduction": step.get("risk_reduction", 0.0),
                "missing_provenance_fields": join_multi(step.get("missing_provenance_fields", [])),
            })

    output_owl.parent.mkdir(parents=True, exist_ok=True)
    graph.serialize(destination=output_owl, format="xml")
    write_csv(
        manifest_csv,
        manifest_rows,
        [
            "playbook_id",
            "source",
            "source_case",
            "source_case_id",
            "source_scenario_id",
            "scenario_name",
            "attack_path_id",
            "attacker_start",
            "attacker_goal",
            "incident_index",
            "playbook_cves",
            "playbook_cvss_scores",
            "playbook_cvss_severities",
                "playbook_attack_techniques",
                "playbook_covered_attack_techniques",
            "playbook_d3fend_techniques",
            "playbook_digital_artifacts",
            "affected_hosts",
            "host_bindings",
            "risk_before",
            "risk_after",
            "playbook_risk_reduction",
            "playbook_risk_reduction_pct",
            "path_length",
            "action_count",
            "lifecycle_phases_present",
            "phase_completeness",
            "step_id",
            "phase",
            "host_binding",
            "cve",
            "cvss_score",
            "cvss_severity",
            "defensive_technique_id",
            "defensive_technique_label",
            "defense_artifact_id",
            "attack_technique_id",
            "matched_attack_technique_id",
            "attack_techniques",
            "attack_technique_label",
            "command",
            "risk_reduction",
            "missing_provenance_fields",
        ],
    )

    print(f"Wrote {len(playbooks)} playbooks to {output_owl}")


if __name__ == "__main__":
    main()
