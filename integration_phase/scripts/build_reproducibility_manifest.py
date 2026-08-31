#!/usr/bin/env python3
"""Capture corpus lineage, artifact hashes, protocol constants, and runtime metadata."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from selection_protocol import CLOSED_LOOP_BALANCED_WEIGHTS, protocol_manifest


REPO_ROOT = Path(__file__).resolve().parents[2]
SELECTION_VENDORS = ("FortiSOAR", "Rapid7", "XSOAR")
PACKAGES = (
    "pandas",
    "numpy",
    "rdflib",
    "requests",
    "SPARQLWrapper",
    "cvss",
    "networkx",
    "xmltodict",
    "matplotlib",
    "sentence-transformers",
    "transformers",
    "tokenizers",
    "huggingface-hub",
    "torch",
    "psutil",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/evaluation/corrected/reproducibility_manifest.json"),
    )
    parser.add_argument(
        "--corpus-summary",
        type=Path,
        default=Path("results/evaluation/corrected/community_corpus_summary.csv"),
    )
    parser.add_argument("--expected-mapping-threshold", type=float, default=0.0)
    parser.add_argument("--run-label", default="paper-evaluation")
    parser.add_argument("--graphdb-version", default=os.getenv("GRAPHDB_VERSION", ""))
    parser.add_argument("--mulval-version", default=os.getenv("MULVAL_VERSION", ""))
    parser.add_argument("--hardware-note", default="")
    return parser.parse_args()


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_record(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    return {
        "path": relative,
        "exists": path.exists(),
        "bytes": path.stat().st_size if path.exists() and path.is_file() else None,
        "sha256": file_sha256(path) if path.exists() and path.is_file() else None,
    }


def tree_record(root: Path, relative: str, pattern: str = "*") -> dict[str, Any]:
    directory = root / relative
    files = sorted(path for path in directory.rglob(pattern) if path.is_file()) if directory.exists() else []
    digest = hashlib.sha256()
    total_bytes = 0
    for path in files:
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        total_bytes += size
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_sha256(path).encode("ascii"))
        digest.update(b"\n")
    return {
        "path": relative,
        "pattern": pattern,
        "exists": directory.exists(),
        "file_count": len(files),
        "bytes": total_bytes,
        "tree_sha256": digest.hexdigest() if files else None,
    }


def read_csv(path: Path, delimiter: str = ",") -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle, delimiter=delimiter))


def corpus_summary(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source_path = root / "selection_phase/source/Playbook/steps-coded.csv"
    filtered_path = root / "selection_phase/source/Playbook-defend-mapping/Preprocessing/filtered_playbooks.csv"
    rows = read_csv(source_path, delimiter=";")
    filtered = read_csv(filtered_path)

    vendors: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        vendors[row.get("vendor", "")].append(row)

    vendor_rows: list[dict[str, Any]] = []
    for vendor in sorted(vendors):
        items = vendors[vendor]
        included = vendor in SELECTION_VENDORS
        vendor_rows.append({
            "vendor": vendor,
            "source_step_rows": len(items),
            "source_playbooks": len({row.get("playbook_id", "") for row in items if row.get("playbook_id")}),
            "selection_ontology_included": str(included),
            "selection_step_rows": len(items) if included else 0,
            "selection_playbooks": len({row.get("playbook_id", "") for row in items if row.get("playbook_id")}) if included else 0,
        })

    selected = [row for row in rows if row.get("vendor") in SELECTION_VENDORS]
    required_fields = (
        "playbook_id",
        "step_id",
        "vendor",
        "playbook_name",
        "playbook_description",
        "step_names",
        "step_description",
        "action",
        "artifact",
    )
    summary = {
        "source_path": source_path.relative_to(root).as_posix(),
        "source_sha256": file_sha256(source_path),
        "source_delimiter": ";",
        "source_rows": len(rows),
        "source_playbooks": len({row.get("playbook_id", "") for row in rows if row.get("playbook_id")}),
        "source_unique_steps": len({row.get("step_id", "") for row in rows if row.get("step_id")}),
        "source_duplicate_step_ids": len(rows) - len({row.get("step_id", "") for row in rows if row.get("step_id")}),
        "vendor_count": len(vendors),
        "missing_values": {
            field: sum(1 for row in rows if not str(row.get(field, "")).strip())
            for field in required_fields
        },
        "semantic_mapping_projection": {
            "path": filtered_path.relative_to(root).as_posix(),
            "sha256": file_sha256(filtered_path),
            "rows": len(filtered),
            "playbooks": len({row.get("playbook_id", "") for row in filtered if row.get("playbook_id")}),
            "steps": len({row.get("step_id", "") for row in filtered if row.get("step_id")}),
            "vendor_filter": list(SELECTION_VENDORS),
        },
        "selection_ontology_filter": {
            "vendors": list(SELECTION_VENDORS),
            "rows": len(selected),
            "playbooks": len({row.get("playbook_id", "") for row in selected if row.get("playbook_id")}),
            "steps": len({row.get("step_id", "") for row in selected if row.get("step_id")}),
        },
    }
    return summary, vendor_rows


def rdf_literal_values(path: Path, local_property: str) -> list[str]:
    values: list[str] = []
    if not path.exists():
        return values
    for _event, element in ElementTree.iterparse(path, events=("end",)):
        if element.tag.rsplit("}", 1)[-1] == local_property and element.text:
            values.append(element.text.strip())
        element.clear()
    return values


def mapping_summary(root: Path, expected_threshold: float) -> dict[str, Any]:
    mapping_path = root / "selection_phase/source/Playbook-defend-mapping/MainPart/playbook_defend_mapping.csv"
    manifest_path = mapping_path.with_name("semantic_mapping_manifest.json")
    rows = read_csv(mapping_path)
    scores = [float(row["Confidence Score"]) for row in rows if row.get("Confidence Score")]
    no_match = sum(row.get("Best Matched D3FEND Technique") == "No Match" for row in rows)
    subthreshold_links = sum(
        row.get("Best Matched D3FEND Technique") != "No Match"
        and float(row.get("Confidence Score") or 0.0) < expected_threshold
        for row in rows
    )
    return {
        "mapping_path": mapping_path.relative_to(root).as_posix(),
        "mapping_sha256": file_sha256(mapping_path),
        "rows": len(rows),
        "playbooks": len({row.get("Playbook ID", "") for row in rows if row.get("Playbook ID")}),
        "steps": len({row.get("Step ID", "") for row in rows if row.get("Step ID")}),
        "no_match_count": no_match,
        "confidence": {
            "minimum": min(scores) if scores else None,
            "mean": sum(scores) / len(scores) if scores else None,
            "maximum": max(scores) if scores else None,
        },
        "expected_threshold": expected_threshold,
        "linked_rows_below_expected_threshold": subthreshold_links,
        "threshold_compatible": subthreshold_links == 0,
        "semantic_mapping_manifest_present": manifest_path.exists(),
        "semantic_mapping_manifest_sha256": (
            file_sha256(manifest_path) if manifest_path.exists() else None
        ),
    }


def package_versions() -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for package in PACKAGES:
        try:
            result[package] = version(package)
        except PackageNotFoundError:
            result[package] = None
    return result


def memory_bytes() -> int | None:
    try:
        return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return None


def cpu_model() -> str | None:
    detected = (platform.processor() or "").strip()
    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    if platform.system() == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
                if line.lower().startswith("model name") and ":" in line:
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    return detected or None


def physical_cpu_count() -> int | None:
    try:
        import psutil
    except ModuleNotFoundError:
        return None
    return psutil.cpu_count(logical=False)


def torch_hardware() -> dict[str, Any]:
    try:
        import torch
    except ModuleNotFoundError:
        return {
            "torch_available": False,
            "cuda_available": None,
            "cuda_device_count": None,
            "cuda_device_names": [],
            "mps_available": None,
        }
    mps = getattr(torch.backends, "mps", None)
    return {
        "torch_available": True,
        "cuda_available": bool(torch.cuda.is_available()),
        "cuda_device_count": int(torch.cuda.device_count()) if torch.cuda.is_available() else 0,
        "cuda_device_names": [
            torch.cuda.get_device_name(index)
            for index in range(torch.cuda.device_count())
        ] if torch.cuda.is_available() else [],
        "mps_available": bool(mps and mps.is_available()),
    }


def runtime_metadata(args: argparse.Namespace) -> dict[str, Any]:
    metadata = {
        "scope": "environment used to generate this public artifact manifest",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "python_executable": Path(sys.executable).name,
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_model": cpu_model(),
        "physical_cpu_count": physical_cpu_count(),
        "logical_cpu_count": os.cpu_count(),
        "physical_memory_bytes": memory_bytes(),
        "accelerators": torch_hardware(),
        "packages": package_versions(),
        "graphdb_endpoint": "http://localhost:7200/repositories/incident-response",
        "mulval_version_recorded": bool(args.mulval_version),
        "hardware_note": args.hardware_note,
        "capture_command": sys.argv,
    }
    if args.graphdb_version:
        metadata["graphdb_version"] = args.graphdb_version
    if args.mulval_version:
        metadata["mulval_version"] = args.mulval_version
    return metadata


def write_vendor_summary(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "vendor",
        "source_step_rows",
        "source_playbooks",
        "selection_ontology_included",
        "selection_step_rows",
        "selection_playbooks",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    root = args.repo_root.resolve()
    output = resolve(root, args.output)
    corpus_output = resolve(root, args.corpus_summary)
    corpus, vendor_rows = corpus_summary(root)
    mapping = mapping_summary(root, args.expected_mapping_threshold)
    acquisition_path = root / "data/community_corpus_acquisition.json"
    acquisition = json.loads(acquisition_path.read_text(encoding="utf-8"))
    graphdb_owl = root / "selection_phase/source/GraphDB/playbooks.owl"
    graphdb_playbook_values = rdf_literal_values(graphdb_owl, "hasPlaybookID")
    graphdb_step_values = rdf_literal_values(graphdb_owl, "hasStepID")

    key_files = [
        "README.md",
        "requirements.txt",
        "requirements-lock.txt",
        "requirements-optional.txt",
        "tests/test_generation_correctness.py",
        "data/scenario_profiles/index.json",
        "data/scenario_profiles/mulval_generation_manifest.json",
        "data/community_corpus_acquisition.json",
        "data/ics_scenario_corpus_acquisition.json",
        "docs/artifact_manifest.md",
        "docs/reproduction.md",
        "selection_phase/source/Playbook/steps-coded.csv",
        "selection_phase/source/GraphDB/playbooks.owl",
        "selection_phase/source/Playbook-defend-mapping/Preprocessing/filtered_playbooks.csv",
        "selection_phase/source/Playbook-defend-mapping/Preprocessing/filtered_defensive_techniques.csv",
        "selection_phase/source/Playbook-defend-mapping/MainPart/playbook_defend_mapping.csv",
        "selection_phase/source/Playbook-defend-mapping/MainPart/playbook-defend-mapping.py",
        "selection_phase/source/GraphDB/playbook_step_defend_mapping.owl",
        "results/generated_repository/k_sweep/k_sensitivity_summary.csv",
        "results/generated_repository/k_sweep/k_sensitivity_summary.json",
        "results/generated_repository/corrected_k03/reduced_generated_playbooks_manifest.csv",
        "results/generated_repository/corrected_k03/reduced_generated_playbooks.owl",
        "results/generated_repository/corrected_k03/reduction_report.csv",
        "results/generated_repository/corrected_k03/reduction_summary.json",
        "results/evaluation/corrected/graphdb_load_verification.json",
        "results/evaluation/corrected/d3fend_relation_runtime_audit.json",
        "results/evaluation/corrected/semantic_mapping_audit.json",
        "results/evaluation/corrected/closed_loop_comparison.csv",
        "results/evaluation/corrected/significance_tests.json",
        "results/evaluation/corrected/determinism_check.json",
        "results/evaluation/corrected/fairness_checks.json",
        "results/evaluation/corrected/sanity_summary.json",
        "results/evaluation/corrected/selection_profiles/profile_summary.csv",
        "results/evaluation/corrected/portfolio/portfolio_summary.csv",
        "results/evaluation/corrected/ablations/ablation_summary.csv",
        "results/evaluation/corrected/reduction_sensitivity/reduction_sensitivity.csv",
        "results/evaluation/corrected/weight_sensitivity/summary.json",
        "results/evaluation/corrected/sbert_mapping_diagnostics.csv",
        "results/evaluation/corrected/sbert_mapping_cutoff_diagnostics.csv",
        "results/evaluation/corrected/publication_tables/publication_outputs_manifest.json",
        "results/evaluation/corrected/source_selection_diagnostics.csv",
        "results/evaluation/corrected/source_weight_stability.csv",
        "results/evaluation/corrected/reduction_effect_by_scenario.csv",
        "results/evaluation/corrected/reduction_alternative_summary.csv",
        "results/evaluation/corrected/generation_diversity_diagnostics.csv",
        "results/evaluation/corrected/generation_diversity_diagnostics.json",
        "results/evaluation/corrected/publication_figures/corrected_generation_diversity.tex",
        "results/evaluation/corrected/publication_figures/corrected_generation_diversity.tex.metadata.json",
        "results/evaluation/corrected/publication_tables/corrected_weak_normalized_profiles.csv",
        "results/evaluation/corrected/publication_tables/corrected_weak_normalized_profiles.csv.metadata.json",
        "results/evaluation/corrected/publication_figures/corrected_weak_normalized_profiles.tex",
        "results/evaluation/corrected/publication_figures/corrected_weak_normalized_profiles.tex.metadata.json",
        "results/ics_scenario_inventory.csv",
        "results/ics_scenario_jaccard.csv",
        "results/ics_scenario_summary.json",
    ]
    payload = {
        "manifest_version": "artifact-v0.2",
        "run_label": args.run_label,
        "repository_root": ".",
        "corpus": {
            **corpus,
            "selection_owl_observed": {
                "canonical_graphdb_input": {
                    "path": graphdb_owl.relative_to(root).as_posix(),
                    "sha256": file_sha256(graphdb_owl),
                    "playbook_id_triples": len(graphdb_playbook_values),
                    "unique_playbook_ids": len(set(graphdb_playbook_values)),
                    "step_id_triples": len(graphdb_step_values),
                    "unique_step_ids": len(set(graphdb_step_values)),
                },
            },
            "acquisition": acquisition,
        },
        "semantic_mapping": mapping,
        "generation": {
            "countermeasure_k_values": list(range(0, 11)),
            "paper_configuration_k": 3,
            "supplemental_k_sensitivity": list(range(0, 11)),
            "configured_topology_seed": 42,
            "configured_per_scenario_topology_seed": "42 + zero-based scenario index",
            "configured_incident_seed": 1337,
            "seed_environment_variable": "INCIDENT_SEED",
            "fixed_attack_graphs_in_main_evaluation": True,
            "seed_scope": (
                "The K=0..10 sweep uses the checked-in attack graphs and "
                "INCIDENT_SEED=1337."
            ),
        },
        "reduction": {
            "strategy": "hybrid",
            "per_scenario_limit": 50,
            "algorithm_source": "integration_phase/scripts/reduce_generated_playbooks.py",
            "tie_policy": "lexicographically smallest stable playbook_id after numeric objectives",
            "evaluated_k03": {
                "input_playbooks": 7928,
                "selected_playbooks": 167,
                "status": "evaluated generation and relative-risk reducer",
            },
        },
        "selection": protocol_manifest(
            weights=CLOSED_LOOP_BALANCED_WEIGHTS,
            missing_context_policy="neutral",
        ),
        "statistical_protocol": {
            "bootstrap_seed": 12345,
            "bootstrap_samples": 10000,
            "weight_sensitivity_seed": 20260714,
            "weight_draws": 5000,
            "rng": "numpy.random.Generator(PCG64)",
            "unit_of_analysis": "16 paired sector scenarios",
        },
        "runtime": runtime_metadata(args),
        "artifacts": [artifact_record(root, relative) for relative in key_files],
        "artifact_trees": [
            tree_record(root, "data/scenario_profiles", "*.json"),
            tree_record(root, "results/evaluation/corrected/community-only/candidate_scores_per_scenario", "*.csv"),
            tree_record(root, "results/evaluation/corrected/generated-reduced/candidate_scores_per_scenario", "*.csv"),
            tree_record(root, "results/evaluation/corrected/augmented-reduced/candidate_scores_per_scenario", "*.csv"),
            tree_record(root, "results/evaluation/corrected/weight_sensitivity", "*.csv"),
            tree_record(root, "results/evaluation/corrected/publication_tables", "*"),
            tree_record(root, "results/evaluation/corrected/publication_figures", "*"),
            tree_record(root, "integration_phase/scripts", "*.py"),
            tree_record(root, "generation_phase/source", "*.py"),
            tree_record(root, "selection_phase/source", "*.py"),
            tree_record(root, "tests", "*.py"),
        ],
        "scope_limits": [
            "Complete upstream acquisition metadata is unavailable for parts of the community corpus.",
            "The semantic mapping has no expert-labelled precision or recall evaluation.",
            "The K=0..10 sweep is conditional on the checked-in attack graphs and incident seed.",
            "The MulVAL version used to create the checked-in graphs was not recorded.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_vendor_summary(corpus_output, vendor_rows)
    print(f"Wrote reproducibility manifest to {output}")
    print(f"Wrote community corpus summary to {corpus_output}")


if __name__ == "__main__":
    main()
