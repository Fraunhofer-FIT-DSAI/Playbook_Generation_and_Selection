#!/usr/bin/env python3
"""Verify that GraphDB contains the evaluated repository state."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

from closed_loop_common import repo_display_path, repo_path, write_json


IRSO = "http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#"
D3FEND = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
DEFAULT_ENDPOINT = "http://localhost:7200/repositories/incident-response"
DEFAULT_INPUTS = (
    Path("selection_phase/source/IncidentResponseSecurityOntology.rdf"),
    Path("selection_phase/source/GraphDB/d3fend.owl"),
    Path("selection_phase/source/GraphDB/playbooks.owl"),
    Path("selection_phase/source/GraphDB/playbook_step_defend_mapping.owl"),
    Path("results/generated_repository/corrected_k03/reduced_generated_playbooks.owl"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(
            "results/generated_repository/corrected_k03/"
            "reduced_generated_playbooks_manifest.csv"
        ),
    )
    parser.add_argument("--input", action="append", type=Path, dest="inputs")
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("results/evaluation/corrected/graphdb_load_verification.json"),
    )
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def query(endpoint: str, sparql: str, *, infer: bool) -> list[dict[str, dict[str, str]]]:
    response = requests.get(
        endpoint,
        params={"query": sparql, "infer": str(infer).lower()},
        headers={"Accept": "application/sparql-results+json"},
        timeout=180,
    )
    response.raise_for_status()
    return response.json()["results"]["bindings"]


def scalar_counts(endpoint: str, *, infer: bool) -> dict[str, int]:
    sparql = f"""
PREFIX irso: <{IRSO}>
SELECT ?total ?identifiedPlaybooks ?communityPlaybooks ?generatedPlaybooks
       ?identifiedSteps ?communitySteps ?generatedSteps ?mappingLinks
       ?relativeRiskPlaybooks ?d3fendNamespaceTriples
WHERE {{
  {{ SELECT (COUNT(*) AS ?total) WHERE {{ ?s ?p ?o }} }}
  {{ SELECT (COUNT(DISTINCT ?p) AS ?identifiedPlaybooks)
     WHERE {{ ?p irso:hasPlaybookID ?id }} }}
  {{ SELECT (COUNT(DISTINCT ?p) AS ?communityPlaybooks)
     WHERE {{
       ?p irso:hasPlaybookID ?id .
       FILTER NOT EXISTS {{ ?p irso:source "generated" }}
     }} }}
  {{ SELECT (COUNT(DISTINCT ?p) AS ?generatedPlaybooks)
     WHERE {{ ?p irso:hasPlaybookID ?id ; irso:source "generated" }} }}
  {{ SELECT (COUNT(DISTINCT ?s) AS ?identifiedSteps)
     WHERE {{ ?s irso:hasStepID ?id }} }}
  {{ SELECT (COUNT(DISTINCT ?s) AS ?communitySteps)
     WHERE {{
       ?s irso:hasStepID ?id .
       FILTER NOT EXISTS {{ ?s irso:source "generated" }}
     }} }}
  {{ SELECT (COUNT(DISTINCT ?s) AS ?generatedSteps)
     WHERE {{ ?s irso:hasStepID ?id ; irso:source "generated" }} }}
  {{ SELECT (COUNT(*) AS ?mappingLinks)
     WHERE {{
       ?s irso:hasStepID ?id ; irso:usesDefensiveTechnique ?d .
       FILTER NOT EXISTS {{ ?s irso:source "generated" }}
     }} }}
  {{ SELECT (COUNT(DISTINCT ?p) AS ?relativeRiskPlaybooks)
     WHERE {{ ?p irso:hasPlaybookID ?id ; irso:hasRelativeRiskReduction ?rr }} }}
  {{ SELECT (COUNT(*) AS ?d3fendNamespaceTriples)
     WHERE {{
       ?s ?p ?o .
       FILTER(
         STRSTARTS(STR(?s), "{D3FEND}") ||
         STRSTARTS(STR(?p), "{D3FEND}") ||
         (isIRI(?o) && STRSTARTS(STR(?o), "{D3FEND}"))
       )
     }} }}
}}
"""
    rows = query(endpoint, sparql, infer=infer)
    if len(rows) != 1:
        raise RuntimeError(f"Expected one count row, received {len(rows)}.")
    return {name: int(value["value"]) for name, value in rows[0].items()}


def generated_ids(endpoint: str) -> dict[str, str]:
    sparql = f"""
PREFIX irso: <{IRSO}>
SELECT ?id ?scenario
WHERE {{
  ?p irso:hasPlaybookID ?id ; irso:source "generated" .
  OPTIONAL {{ ?p irso:sourceScenarioId ?scenario }}
}}
ORDER BY ?id
"""
    rows = query(endpoint, sparql, infer=False)
    return {
        row["id"]["value"]: row.get("scenario", {}).get("value", "")
        for row in rows
    }


def manifest_ids(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            playbook_id = row.get("playbook_id", "").strip()
            if playbook_id:
                result[playbook_id] = row.get("source_scenario_id", "").strip()
    return result


def graphdb_metadata(endpoint: str) -> tuple[dict[str, object], dict[str, object]]:
    parsed = urlsplit(endpoint)
    base = f"{parsed.scheme}://{parsed.netloc}"
    repository_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    repositories_response = requests.get(f"{base}/rest/repositories", timeout=60)
    repositories_response.raise_for_status()
    repository = next(
        (
            item
            for item in repositories_response.json()
            if item.get("id") == repository_id
        ),
        None,
    )
    if repository is None:
        raise RuntimeError(f"GraphDB repository {repository_id!r} was not found.")
    details_response = requests.get(
        f"{base}/rest/repositories/{repository_id}", timeout=60
    )
    details_response.raise_for_status()
    repository["params"] = details_response.json().get("params", {})
    version = requests.get(f"{base}/rest/info/version", timeout=60)
    version.raise_for_status()
    return repository, version.json()


def main() -> int:
    args = parse_args()
    manifest = repo_path(args.manifest)
    out_json = repo_path(args.out_json)
    assert manifest is not None and out_json is not None

    input_paths = [repo_path(path) for path in (args.inputs or DEFAULT_INPUTS)]
    if any(path is None or not path.exists() for path in input_paths):
        missing = [
            str(path)
            for path in input_paths
            if path is None or not path.exists()
        ]
        raise FileNotFoundError(f"Missing GraphDB input: {', '.join(missing)}")
    if not manifest.exists():
        raise FileNotFoundError(manifest)

    manifest_map = manifest_ids(manifest)
    graphdb_map = generated_ids(args.endpoint)
    explicit_counts = scalar_counts(args.endpoint, infer=False)
    inferred_counts = scalar_counts(args.endpoint, infer=True)
    repository, version = graphdb_metadata(args.endpoint)

    missing_ids = sorted(set(manifest_map) - set(graphdb_map))
    extra_ids = sorted(set(graphdb_map) - set(manifest_map))
    scenario_mismatches = sorted(
        playbook_id
        for playbook_id in set(manifest_map) & set(graphdb_map)
        if manifest_map[playbook_id] != graphdb_map[playbook_id]
    )
    checks = {
        "repository_running": repository.get("state") == "RUNNING",
        "repository_readable": repository.get("readable") is True,
        "repository_writable": repository.get("writable") is True,
        "community_playbooks_equal_469": explicit_counts["communityPlaybooks"] == 469,
        "community_steps_equal_4016": explicit_counts["communitySteps"] == 4016,
        "community_mapping_links_equal_4016": explicit_counts["mappingLinks"] == 4016,
        "generated_playbooks_equal_manifest": (
            explicit_counts["generatedPlaybooks"] == len(manifest_map)
        ),
        "generated_manifest_ids_match_graphdb": not missing_ids and not extra_ids,
        "generated_scenarios_match_manifest": not scenario_mismatches,
        "all_generated_playbooks_have_relative_risk": (
            explicit_counts["relativeRiskPlaybooks"]
            == explicit_counts["generatedPlaybooks"]
        ),
        "d3fend_namespace_present": explicit_counts["d3fendNamespaceTriples"] > 0,
    }
    if len(manifest_map) == 167:
        checks["corrected_generated_playbooks_equal_167"] = (
            explicit_counts["generatedPlaybooks"] == 167
        )

    command = " ".join(shlex.quote(arg) for arg in ["python", *sys.argv])
    payload = {
        "status": "pass" if all(checks.values()) else "fail",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "endpoint": args.endpoint,
        "repository": {
            "id": repository.get("id"),
            "state": repository.get("state"),
            "readable": repository.get("readable"),
            "writable": repository.get("writable"),
            "ruleset": (
                repository.get("params", {})
                .get("ruleset", {})
                .get("value")
            ),
        },
        "graphdb_version": version,
        "input_files": [
            {
                "path": repo_display_path(path),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in input_paths
            if path is not None
        ],
        "manifest": {
            "path": repo_display_path(manifest),
            "bytes": manifest.stat().st_size,
            "sha256": sha256(manifest),
            "unique_playbooks": len(manifest_map),
            "per_scenario": dict(sorted(Counter(manifest_map.values()).items())),
        },
        "explicit_counts": explicit_counts,
        "counts_with_inference": inferred_counts,
        "generated_id_comparison": {
            "graphdb_ids": len(graphdb_map),
            "manifest_ids": len(manifest_map),
            "missing_ids": missing_ids,
            "extra_ids": extra_ids,
            "scenario_mismatches": scenario_mismatches,
        },
        "checks": checks,
        "interpretation": (
            "Mapping counts and graph equality establish artifact integrity only; "
            "they do not establish semantic accuracy."
        ),
    }
    write_json(out_json, payload)
    print(json.dumps(payload, indent=2))
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
