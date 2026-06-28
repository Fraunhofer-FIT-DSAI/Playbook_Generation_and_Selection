from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]


def repo_path(path: Path | str | None) -> Path | None:
    if path is None:
        return None
    path = Path(path)
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def repo_display_path(path: Path | str | None) -> str:
    if path is None:
        return ""
    path = Path(path)
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


DEFAULT_SCENARIOS = [
    "Chemical",
    "Commercial Facilities",
    "Communications",
    "Critical Manufacturing",
    "Dams",
    "Defense Industrial Base",
    "Emergency Services",
    "Energy",
    "Financial Services",
    "Food and Agriculture",
    "Government Facilities",
    "Healthcare and Public Health",
    "Information Technology",
    "Nuclear Reactors, Materials, and Waste",
    "Transportation Systems",
    "Water and Wastewater Systems",
]

LEGACY_MODES = ["community-only", "generated-only", "augmented"]
EVALUATION_MODES = [
    "community-only",
    "generated-only",
    "generated-all",
    "generated-reduced",
    "augmented",
    "augmented-all",
    "augmented-reduced",
]

MODE_ALIASES = {
    "generated-only": "generated-all",
    "augmented": "augmented-all",
}

GENERATED_REDUCED_MODES = {"generated-reduced", "augmented-reduced"}


def safe_id(value: str) -> str:
    value = str(value).strip()
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "unknown"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def read_csv_dicts(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def split_multi(value_text: Any) -> list[str]:
    if value_text is None:
        return []
    if isinstance(value_text, (list, tuple, set)):
        values = value_text
    else:
        text = str(value_text).strip()
        if not text:
            return []
        values = re.split(r"[;,]", text)
    result = []
    seen = set()
    for item in values:
        text = str(item).strip()
        if text and text not in seen:
            result.append(text)
            seen.add(text)
    return result


def join_multi(values: Iterable[Any]) -> str:
    return ";".join(sorted({str(value).strip() for value in values if str(value).strip()}))


def to_float(value_text: Any, default: float = 0.0) -> float:
    try:
        text = str(value_text).strip()
        if not text:
            return default
        if text.endswith("%"):
            text = text[:-1]
        return float(text)
    except (TypeError, ValueError):
        return default


def scenario_query_path(project_root: Path, scenario_name: str) -> Path:
    return (
        project_root
        / "Use-Case"
        / "SparqlQueryGeneration"
        / "SPARQL_QUERIES"
        / f"df_SCENARIO_{scenario_name}.sparql"
    )


def iter_scenario_paths(project_root: Path, scenarios: list[str] | None = None) -> list[tuple[str, Path]]:
    selected = scenarios or DEFAULT_SCENARIOS
    result = []
    for scenario in selected:
        path = scenario_query_path(project_root, scenario)
        if not path.exists():
            raise FileNotFoundError(f"Missing scenario query: {path}")
        result.append((scenario, path))
    return result


def technique_ids_from_sparql(path: Path) -> set[str]:
    text = read_text(path)
    pattern = r"VALUES\s+\?attackId\s*\{(.*?)\}"
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        return set()
    block = match.group(1)
    return set(re.findall(r"d3fend\.owl#(T[0-9]+(?:\.[0-9]+)?)", block))


def scenario_values_block(path: Path) -> str:
    text = read_text(path)
    pattern = r"VALUES\s+\?attackId\s*\{(.*?)\}"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else ""


def scenario_universe_query(path: Path) -> str:
    values_block = scenario_values_block(path)
    if not values_block:
        return ""
    return f"""
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?attackId ?defenseRelationship ?artifact
WHERE {{
  VALUES ?attackId {{
    {values_block}
  }}

  {{
    ?attackId ?artifactRelationship ?artifact .
    ?artifactRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
  }}
  UNION
  {{
    ?attackId rdfs:subClassOf+ ?ancestor .
    ?ancestor ?inheritedArtifactRelationship ?artifact .
    ?inheritedArtifactRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
  }}

  ?artifact rdfs:label ?artifactLabel .
  ?defensiveTechnique ?defenseRelationship ?artifact .
  ?defenseRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
  ?defensiveTechnique rdf:type d3f:DefensiveTechnique .
}}
"""


def sparql_string(value_text: str) -> str:
    return json.dumps(str(value_text))


def playbook_id_filter_clause(
    mode: str,
    generated_prefix: str,
    scenario_name: str | None = None,
    match_generated_source_case: bool = False,
    allowed_generated_ids: set[str] | None = None,
) -> str:
    mode = canonical_mode(mode)
    generated_prefix_literal = sparql_string(generated_prefix)
    scenario_generated_prefix = (
        generated_case_prefix(scenario_name, generated_prefix)
        if scenario_name and match_generated_source_case
        else generated_prefix
    )
    scenario_generated_prefix_literal = sparql_string(scenario_generated_prefix)
    allowed_ids = sorted(allowed_generated_ids or [])
    if scenario_name and match_generated_source_case and allowed_ids:
        expected_prefix = generated_case_prefix(scenario_name, generated_prefix)
        allowed_ids = [playbook_id for playbook_id in allowed_ids if playbook_id.startswith(expected_prefix)]

    if mode == "community-only":
        return f"FILTER(!STRSTARTS(STR(?playbookID), {generated_prefix_literal}))"

    if mode == "generated-reduced":
        if not allowed_ids:
            return "FILTER(false)"
        values = " ".join(sparql_string(playbook_id) for playbook_id in allowed_ids)
        return f"VALUES ?playbookID {{ {values} }}"

    if mode == "augmented-reduced":
        if not allowed_ids:
            return f"FILTER(!STRSTARTS(STR(?playbookID), {generated_prefix_literal}))"
        values = ", ".join(sparql_string(playbook_id) for playbook_id in allowed_ids)
        return (
            f"FILTER(!STRSTARTS(STR(?playbookID), {generated_prefix_literal}) "
            f"|| ?playbookID IN ({values}))"
        )

    if mode == "generated-all":
        return f"FILTER(STRSTARTS(STR(?playbookID), {scenario_generated_prefix_literal}))"

    if mode == "augmented-all":
        if match_generated_source_case and scenario_name:
            return (
                f"FILTER(!STRSTARTS(STR(?playbookID), {generated_prefix_literal}) "
                f"|| STRSTARTS(STR(?playbookID), {scenario_generated_prefix_literal}))"
            )
        return ""

    return ""


def scenario_direct_attack_query(
    path: Path,
    playbook_filter: str = "",
) -> str:
    values_block = scenario_values_block(path)
    if not values_block:
        return ""
    playbook_filter_block = f"\n  {playbook_filter}\n" if playbook_filter else ""
    return f"""
PREFIX irso: <http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#>
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT DISTINCT
  ?playbookID ?stepID ?attackId ?directScope ?source ?sourceCase ?sourceScenario
  ?attackPath ?cve ?targetHost ?riskReduction ?riskBefore ?riskAfter
  ?phase ?actionCount ?phaseCompleteness
WHERE {{
  VALUES ?attackId {{
    {values_block}
  }}

  ?playbook rdf:type irso:Playbook .
  ?playbook irso:hasPlaybookID ?playbookID .
  {playbook_filter_block}

  {{
    ?playbook irso:coversAttackTechnique ?attackId .
    BIND("playbook-covers" AS ?directScope)
  }}
  UNION
  {{
    ?playbook irso:generatedForAttackTechnique ?attackId .
    BIND("playbook-generated-for" AS ?directScope)
  }}
  UNION
  {{
    ?playbook irso:hasStep ?step .
    ?step irso:generatedForAttackTechnique ?attackId .
    OPTIONAL {{ ?step irso:hasStepID ?stepID . }}
    OPTIONAL {{ ?step irso:hasResponsePhase ?phase . }}
    OPTIONAL {{ ?step irso:addressesCVE ?cve . }}
    OPTIONAL {{ ?step irso:targetsHost ?targetHost . }}
    BIND("step-generated-for" AS ?directScope)
  }}

  OPTIONAL {{ ?playbook irso:source ?source . }}
  OPTIONAL {{ ?playbook irso:generatedFromSource ?source . }}
  OPTIONAL {{ ?playbook irso:generatedFromCase ?sourceCase . }}
  OPTIONAL {{ ?playbook irso:sourceCaseId ?sourceCase . }}
  OPTIONAL {{ ?playbook irso:derivedFromScenario ?sourceScenario . }}
  OPTIONAL {{ ?playbook irso:sourceScenarioId ?sourceScenario . }}
  OPTIONAL {{ ?playbook irso:derivedFromAttackPath ?attackPath . }}
  OPTIONAL {{ ?playbook irso:addressesCVE ?cve . }}
  OPTIONAL {{ ?playbook irso:targetsHost ?targetHost . }}
  OPTIONAL {{ ?playbook irso:hasRiskReduction ?riskReduction . }}
  OPTIONAL {{ ?playbook irso:hasRiskBefore ?riskBefore . }}
  OPTIONAL {{ ?playbook irso:hasRiskAfter ?riskAfter . }}
  OPTIONAL {{ ?playbook irso:actionCount ?actionCount . }}
  OPTIONAL {{ ?playbook irso:phaseCompleteness ?phaseCompleteness . }}
}}
"""


def scenario_generated_metadata_query(path: Path) -> str:
    values_block = scenario_values_block(path)
    if not values_block:
        return ""
    return f"""
PREFIX irso: <http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#>
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT DISTINCT
  ?playbookID ?source ?sourceCase ?sourceScenario ?attackPath ?cve ?targetHost
  ?riskReduction ?riskBefore ?riskAfter ?actionCount ?phaseCompleteness
WHERE {{
  ?playbook rdf:type irso:Playbook .
  ?playbook irso:hasPlaybookID ?playbookID .
  OPTIONAL {{ ?playbook irso:source ?source . }}
  OPTIONAL {{ ?playbook irso:generatedFromSource ?source . }}
  OPTIONAL {{ ?playbook irso:generatedFromCase ?sourceCase . }}
  OPTIONAL {{ ?playbook irso:sourceCaseId ?sourceCase . }}
  OPTIONAL {{ ?playbook irso:derivedFromScenario ?sourceScenario . }}
  OPTIONAL {{ ?playbook irso:sourceScenarioId ?sourceScenario . }}
  OPTIONAL {{ ?playbook irso:derivedFromAttackPath ?attackPath . }}
  OPTIONAL {{ ?playbook irso:addressesCVE ?cve . }}
  OPTIONAL {{ ?playbook irso:targetsHost ?targetHost . }}
  OPTIONAL {{ ?playbook irso:hasRiskReduction ?riskReduction . }}
  OPTIONAL {{ ?playbook irso:hasRiskBefore ?riskBefore . }}
  OPTIONAL {{ ?playbook irso:hasRiskAfter ?riskAfter . }}
  OPTIONAL {{ ?playbook irso:actionCount ?actionCount . }}
  OPTIONAL {{ ?playbook irso:phaseCompleteness ?phaseCompleteness . }}
  OPTIONAL {{
    VALUES ?scenarioAttackId {{
      {values_block}
    }}
    ?playbook irso:coversAttackTechnique ?scenarioAttackId .
  }}
}}
"""


def execute_sparql(endpoint: str, query: str) -> list[dict[str, dict[str, str]]]:
    from SPARQLWrapper import JSON, SPARQLWrapper

    sparql = SPARQLWrapper(endpoint)
    sparql.setQuery(query)
    sparql.setReturnFormat(JSON)
    results = sparql.query().convert()
    return results["results"]["bindings"]


def execute_scenario_query(endpoint: str, sparql_file: Path) -> list[dict[str, dict[str, str]]]:
    return execute_sparql(endpoint, read_text(sparql_file))


def execute_scenario_universe_query(endpoint: str, sparql_file: Path) -> list[dict[str, dict[str, str]]]:
    query = scenario_universe_query(sparql_file)
    return execute_sparql(endpoint, query) if query else []


def execute_scenario_direct_attack_query(endpoint: str, sparql_file: Path) -> list[dict[str, dict[str, str]]]:
    query = scenario_direct_attack_query(sparql_file)
    return execute_sparql(endpoint, query) if query else []


def execute_filtered_scenario_direct_attack_query(
    endpoint: str,
    sparql_file: Path,
    mode: str,
    generated_prefix: str,
    scenario_name: str | None = None,
    match_generated_source_case: bool = False,
    allowed_generated_ids: set[str] | None = None,
) -> list[dict[str, dict[str, str]]]:
    playbook_filter = playbook_id_filter_clause(
        mode,
        generated_prefix,
        scenario_name=scenario_name,
        match_generated_source_case=match_generated_source_case,
        allowed_generated_ids=allowed_generated_ids,
    )
    query = scenario_direct_attack_query(sparql_file, playbook_filter)
    return execute_sparql(endpoint, query) if query else []


def execute_scenario_generated_metadata_query(endpoint: str, sparql_file: Path) -> list[dict[str, dict[str, str]]]:
    query = scenario_generated_metadata_query(sparql_file)
    return execute_sparql(endpoint, query) if query else []


def value(row: dict[str, dict[str, str]], key: str, default: str = "") -> str:
    return row.get(key, {}).get("value", default)


def local_name(uri: str) -> str:
    if "#" in uri:
        return uri.rsplit("#", 1)[1]
    return uri.rstrip("/").rsplit("/", 1)[-1]


def classify_playbook(playbook_id: str, generated_prefix: str) -> str:
    return "generated" if playbook_id.startswith(generated_prefix) else "community"


def canonical_mode(mode: str) -> str:
    return MODE_ALIASES.get(mode, mode)


def keep_playbook(playbook_id: str, mode: str, generated_prefix: str) -> bool:
    source = classify_playbook(playbook_id, generated_prefix)
    mode = canonical_mode(mode)
    if mode in {"augmented-all", "augmented-reduced"}:
        return True
    if mode == "community-only":
        return source == "community"
    if mode in {"generated-all", "generated-reduced"}:
        return source == "generated"
    raise ValueError(f"Unknown mode: {mode}")


def generated_case_prefix(scenario_name: str, generated_prefix: str) -> str:
    return f"{generated_prefix}scenario_{safe_id(scenario_name)}_"


def expected_source_case_id(scenario_name: str) -> str:
    return "scenario_" + safe_id(scenario_name)


def expected_source_scenario_id(scenario_name: str) -> str:
    return safe_id(scenario_name)


def source_case_from_playbook_id(playbook_id: str, generated_prefix: str) -> str:
    if not playbook_id.startswith(generated_prefix):
        return ""
    rest = playbook_id[len(generated_prefix):]
    return re.sub(r"_[0-9]+$", "", rest)


def filter_rows(
    rows: list[dict[str, dict[str, str]]],
    mode: str,
    generated_prefix: str,
    scenario_name: str | None = None,
    match_generated_source_case: bool = False,
    allowed_generated_ids: set[str] | None = None,
) -> list[dict[str, dict[str, str]]]:
    kept = []
    expected_case = expected_source_case_id(scenario_name) if scenario_name else ""
    expected_scenario = expected_source_scenario_id(scenario_name) if scenario_name else ""
    for row in rows:
        playbook_id = value(row, "playbookID")
        if not playbook_id or not keep_playbook(playbook_id, mode, generated_prefix):
            continue
        if classify_playbook(playbook_id, generated_prefix) == "generated":
            if allowed_generated_ids is not None and playbook_id not in allowed_generated_ids:
                continue
            if match_generated_source_case and scenario_name:
                row_case = value(row, "sourceCase") or value(row, "source_case") or source_case_from_playbook_id(playbook_id, generated_prefix)
                row_scenario = value(row, "sourceScenario") or value(row, "source_scenario_id")
                if row_case and row_case != expected_case:
                    continue
                if row_scenario and row_scenario != expected_scenario:
                    continue
                if not row_case and not row_scenario and not playbook_id.startswith(generated_case_prefix(scenario_name, generated_prefix)):
                    continue
        kept.append(row)
    return kept


def load_allowed_generated_ids(path: Path | str | None) -> set[str] | None:
    if path is None:
        return None
    resolved = repo_path(path)
    if resolved is None or not resolved.exists():
        return None
    rows = read_csv_dicts(resolved)
    ids = {row.get("playbook_id", "").strip() for row in rows if row.get("playbook_id", "").strip()}
    return ids or None


def load_scenario_profile(profile_dir: Path, scenario_name: str) -> dict[str, Any]:
    path = profile_dir / f"{safe_id(scenario_name)}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def scenario_profile_cves(profile: dict[str, Any]) -> set[str]:
    return {
        str(step.get("top_cve", "")).strip()
        for step in profile.get("steps", [])
        if str(step.get("top_cve", "")).strip()
    }


def playbook_id_value(row: dict[str, dict[str, str]]) -> str:
    return value(row, "playbookID")


def coverage_by_playbook(
    rows: list[dict[str, dict[str, str]]],
    field: str,
    localize: bool = True,
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for row in rows:
        playbook_id = playbook_id_value(row)
        raw_value = value(row, field)
        if not playbook_id or not raw_value:
            continue
        result.setdefault(playbook_id, set()).add(local_name(raw_value) if localize else raw_value)
    return result


def metadata_by_playbook(rows: list[dict[str, dict[str, str]]]) -> dict[str, dict[str, set[str] | str]]:
    multi_fields = {
        "source": "sources",
        "sourceCase": "source_cases",
        "sourceScenario": "source_scenarios",
        "attackPath": "attack_paths",
        "cve": "cves",
        "targetHost": "target_hosts",
        "phase": "phases",
    }
    scalar_fields = {
        "riskReduction": "risk_reduction",
        "riskBefore": "risk_before",
        "riskAfter": "risk_after",
        "actionCount": "action_count",
        "phaseCompleteness": "phase_completeness",
    }
    result: dict[str, dict[str, set[str] | str]] = {}
    for row in rows:
        playbook_id = playbook_id_value(row)
        if not playbook_id:
            continue
        item = result.setdefault(playbook_id, {target: set() for target in multi_fields.values()})
        for source, target in multi_fields.items():
            raw = value(row, source)
            if raw:
                casted = item.setdefault(target, set())
                if isinstance(casted, set):
                    casted.add(local_name(raw) if raw.startswith("http") else raw)
        for source, target in scalar_fields.items():
            raw = value(row, source)
            if raw and not item.get(target):
                item[target] = raw
    return result


def playbook_sources(playbook_ids: Iterable[str], generated_prefix: str) -> str:
    sources = {classify_playbook(pb, generated_prefix) for pb in playbook_ids if pb}
    if not sources:
        return ""
    if len(sources) == 1:
        return next(iter(sources))
    return "mixed"


def parse_percent(value_text: str) -> float | None:
    value_text = str(value_text).strip()
    if not value_text:
        return None
    if value_text.endswith("%"):
        value_text = value_text[:-1]
    return float(value_text)


def split_playbook_ids(value_text: str) -> list[str]:
    return [item.strip() for item in str(value_text).split(",") if item.strip()]
