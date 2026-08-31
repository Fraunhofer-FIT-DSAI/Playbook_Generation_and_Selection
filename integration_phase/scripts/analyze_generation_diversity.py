#!/usr/bin/env python3
"""Measure diversity in the full and retained K=3 generated repositories."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import re
import tarfile
from collections import Counter
from pathlib import Path
from typing import Any, Hashable, Iterable

import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSONL = Path(
    "results/generated_repository/full_k03/export/generated_playbooks.jsonl"
)
DEFAULT_MANIFEST = Path(
    "results/generated_repository/corrected_k03/"
    "reduced_generated_playbooks_manifest.csv"
)
DEFAULT_CSV = Path(
    "results/evaluation/corrected/generation_diversity_diagnostics.csv"
)
DEFAULT_JSON = Path(
    "results/evaluation/corrected/generation_diversity_diagnostics.json"
)
DEFAULT_TEX = Path(
    "results/evaluation/corrected/publication_figures/"
    "corrected_generation_diversity.tex"
)
ARCHIVE_MEMBER = (
    "results/generated_repository/full_k03/export/generated_playbooks.jsonl"
)
ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
REQUIRED_INCIDENT_FIELDS = {
    "cve",
    "cvss",
    "exploitability",
    "host",
    "impact",
    "mitre",
}
METRIC_ORDER = (
    "attack_techniques",
    "hosts",
    "cves",
    "step_evidence_triples",
)
FIGURE_METRICS = METRIC_ORDER
METRIC_LABELS = {
    "attack_techniques": "ATT&CK",
    "hosts": "Hosts",
    "cves": "CVEs",
    "step_evidence_triples": "Path triples",
}
METRIC_DEFINITIONS = {
    "attack_techniques": "ATT&CK technique identifiers observed on each incident path",
    "hosts": "host identifiers observed on each incident path",
    "cves": "CVE identifiers observed on each incident path",
    "step_evidence_triples": (
        "(host, CVE, ATT&CK technique) incident-step triples observed on each path"
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--input-jsonl",
        type=Path,
        help=f"Unreduced K=3 JSONL (default: {DEFAULT_JSONL.as_posix()}).",
    )
    source.add_argument(
        "--release-archive",
        type=Path,
        help="v0.2 large-artifact tar.gz containing the unreduced K=3 JSONL.",
    )
    parser.add_argument("--reduced-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--out-tex", type=Path, default=DEFAULT_TEX)
    parser.add_argument("--expected-full-count", type=int, default=7928)
    parser.add_argument("--expected-reduced-count", type=int, default=167)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def resolve_repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def repo_display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return resolved.name


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl_bytes(lines: Iterable[bytes]) -> tuple[list[dict[str, Any]], str]:
    records: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for line_number, line in enumerate(lines, start=1):
        digest.update(line)
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL record at line {line_number}") from exc
    return records, digest.hexdigest()


def read_full_records(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if args.release_archive:
        archive = resolve_repo_path(args.release_archive)
        with tarfile.open(archive, "r:gz") as bundle:
            candidates = [
                member
                for member in bundle.getmembers()
                if member.isfile() and member.name.endswith("/" + ARCHIVE_MEMBER)
            ]
            if len(candidates) != 1:
                raise ValueError(
                    f"Expected one archive member ending in {ARCHIVE_MEMBER!r}; "
                    f"found {len(candidates)}"
                )
            member = candidates[0]
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise ValueError(f"Could not read {member.name} from {archive.name}")
            records, jsonl_hash = read_jsonl_bytes(extracted)
        return records, {
            "path": ARCHIVE_MEMBER,
            "sha256": jsonl_hash,
            "release_archive": archive.name,
            "release_archive_sha256": sha256_file(archive),
        }

    jsonl = resolve_repo_path(args.input_jsonl or DEFAULT_JSONL)
    with jsonl.open("rb") as handle:
        records, jsonl_hash = read_jsonl_bytes(handle)
    return records, {
        "path": repo_display_path(jsonl),
        "sha256": jsonl_hash,
    }


def read_reduced_ids(path: Path) -> tuple[set[str], str]:
    data = path.read_bytes()
    rows = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    ids = {row.get("playbook_id", "").strip() for row in rows}
    ids.discard("")
    return ids, sha256_bytes(data)


def attack_id(value: Any) -> str:
    matches = ATTACK_ID.findall(str(value))
    if not matches:
        raise ValueError(f"No ATT&CK identifier in incident value {value!r}")
    return matches[-1]


def metric_sequences(
    records: list[dict[str, Any]],
) -> tuple[dict[str, list[list[Hashable]]], int, int]:
    result: dict[str, list[list[Hashable]]] = {
        metric: [] for metric in METRIC_ORDER
    }
    valid_steps = 0
    skipped_steps = 0
    for record in records:
        per_record: dict[str, list[Hashable]] = {
            metric: [] for metric in METRIC_ORDER
        }
        incident = record.get("incident")
        if not isinstance(incident, list):
            raise ValueError(f"Record {record.get('playbook_id')} has no incident list")
        for step in incident:
            if not isinstance(step, dict) or not REQUIRED_INCIDENT_FIELDS.issubset(step):
                skipped_steps += 1
                continue
            host = str(step["host"])
            cve = str(step["cve"])
            technique = attack_id(step["mitre"])
            triple = (host, cve, technique)
            per_record["attack_techniques"].append(technique)
            per_record["hosts"].append(host)
            per_record["cves"].append(cve)
            per_record["step_evidence_triples"].append(triple)
            valid_steps += 1
        for metric in METRIC_ORDER:
            result[metric].append(per_record[metric])
    return result, valid_steps, skipped_steps


def shannon_entropy(sequences: list[list[Hashable]]) -> tuple[float, int, int]:
    counts = Counter(value for sequence in sequences for value in sequence)
    occurrences = sum(counts.values())
    if occurrences == 0:
        return 0.0, 0, 0
    entropy = -sum(
        (count / occurrences) * math.log2(count / occurrences)
        for count in counts.values()
    )
    return entropy, occurrences, len(counts)


def average_pairwise_jaccard(sequences: list[list[Hashable]]) -> float:
    """Return the exact mean over unordered record pairs without materializing pdist."""
    count = len(sequences)
    if count < 2:
        return 0.0
    vocabulary = {value for sequence in sequences for value in sequence}
    if not vocabulary:
        return 0.0
    ordered = sorted(vocabulary, key=repr)
    positions = {value: index for index, value in enumerate(ordered)}
    masks = np.zeros((count, (len(ordered) + 63) // 64), dtype=np.uint64)
    one = np.uint64(1)
    for row_index, sequence in enumerate(sequences):
        for value in set(sequence):
            position = positions[value]
            masks[row_index, position // 64] |= one << np.uint64(position % 64)

    ordered_distance_sum = 0.0
    for start in range(0, count, 128):
        block = masks[start : start + 128]
        intersections = np.bitwise_count(
            np.bitwise_and(block[:, None, :], masks[None, :, :])
        ).sum(axis=2)
        unions = np.bitwise_count(
            np.bitwise_or(block[:, None, :], masks[None, :, :])
        ).sum(axis=2)
        distances = np.divide(
            unions - intersections,
            unions,
            out=np.zeros_like(unions, dtype=float),
            where=unions != 0,
        )
        ordered_distance_sum += float(distances.sum())
    return ordered_distance_sum / (count * (count - 1))


def analyze_corpus(label: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    sequences, valid_steps, skipped_steps = metric_sequences(records)
    metrics: dict[str, Any] = {}
    for metric in METRIC_ORDER:
        entropy, occurrences, unique_values = shannon_entropy(sequences[metric])
        metrics[metric] = {
            "label": METRIC_LABELS[metric],
            "definition": METRIC_DEFINITIONS[metric],
            "pairwise_jaccard_distance": average_pairwise_jaccard(
                sequences[metric]
            ),
            "shannon_entropy_bits": entropy,
            "occurrences": occurrences,
            "unique_values": unique_values,
            "included_in_publication_figure": metric in FIGURE_METRICS,
        }
    scenario_counts = Counter(
        str(record.get("source_scenario_id") or record.get("scenario_name") or "")
        for record in records
    )
    return {
        "label": label,
        "playbooks": len(records),
        "unordered_playbook_pairs": len(records) * (len(records) - 1) // 2,
        "valid_incident_steps": valid_steps,
        "skipped_incident_steps": skipped_steps,
        "scenario_counts": dict(sorted(scenario_counts.items())),
        "metrics": metrics,
    }


def write_csv(path: Path, corpora: dict[str, dict[str, Any]]) -> None:
    fields = [
        "corpus",
        "playbooks",
        "unordered_playbook_pairs",
        "metric",
        "metric_label",
        "pairwise_jaccard_distance",
        "shannon_entropy_bits",
        "occurrences",
        "unique_values",
        "included_in_publication_figure",
        "metric_definition",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for corpus_name, corpus in corpora.items():
            for metric in METRIC_ORDER:
                values = corpus["metrics"][metric]
                writer.writerow(
                    {
                        "corpus": corpus_name,
                        "playbooks": corpus["playbooks"],
                        "unordered_playbook_pairs": corpus[
                            "unordered_playbook_pairs"
                        ],
                        "metric": metric,
                        "metric_label": values["label"],
                        "pairwise_jaccard_distance": (
                            f"{values['pairwise_jaccard_distance']:.12f}"
                        ),
                        "shannon_entropy_bits": (
                            f"{values['shannon_entropy_bits']:.12f}"
                        ),
                        "occurrences": values["occurrences"],
                        "unique_values": values["unique_values"],
                        "included_in_publication_figure": str(
                            values["included_in_publication_figure"]
                        ).lower(),
                        "metric_definition": values["definition"],
                    }
                )


def write_tikz(path: Path, corpus: dict[str, Any]) -> None:
    jaccard = [
        corpus["metrics"][metric]["pairwise_jaccard_distance"]
        for metric in FIGURE_METRICS
    ]
    entropy = [
        corpus["metrics"][metric]["shannon_entropy_bits"]
        for metric in FIGURE_METRICS
    ]
    coordinates_jaccard = " ".join(
        f"({index},{value:.6f})" for index, value in enumerate(jaccard, start=1)
    )
    coordinates_entropy = " ".join(
        f"({index},{value:.6f})" for index, value in enumerate(entropy, start=1)
    )
    content = rf"""\begin{{tikzpicture}}
  \definecolor{{pbblack}}{{HTML}}{{1F2933}}
  \definecolor{{pbblue}}{{HTML}}{{2F6B8A}}
  \definecolor{{pbgold}}{{HTML}}{{A66E20}}
  \begin{{groupplot}}[
    group style={{group size=2 by 1, horizontal sep=1.15cm}},
    width=0.43\linewidth,
    height=3.2cm,
    xtick={{1,2,3,4}},
    xticklabels={{ATT\&CK,Hosts,CVEs,{{Path triples}}}},
    x tick label style={{rotate=20,anchor=east,font=\scriptsize}},
    tick label style={{font=\scriptsize}},
    label style={{font=\small}},
    enlarge x limits=0.16,
    ymajorgrids,
    grid style={{draw=gray!25}},
    axis line style={{draw=pbblack}},
    tick style={{draw=pbblack}},
  ]
    \nextgroupplot[
      ybar,
      bar width=11pt,
      ymin=0,
      ymax=1,
      ytick={{0,0.2,0.4,0.6,0.8,1.0}},
      ylabel={{Jaccard distance}},
      title={{Set-overlap diversity}},
      title style={{font=\small}},
    ]
      \addplot[fill=pbblue,draw=none] coordinates {{{coordinates_jaccard}}};

    \nextgroupplot[
      ybar,
      bar width=11pt,
      ymin=0,
      ymax=7.2,
      ytick={{0,2,4,6}},
      ylabel={{Shannon entropy (bits)}},
      title={{Distributional diversity}},
      title style={{font=\small}},
    ]
      \addplot[fill=pbgold,draw=none] coordinates {{{coordinates_entropy}}};
  \end{{groupplot}}
\end{{tikzpicture}}
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def canonical_command(args: argparse.Namespace) -> str:
    return (
        "python integration_phase/scripts/analyze_generation_diversity.py "
        f"--input-jsonl {ARCHIVE_MEMBER} "
        f"--reduced-manifest {repo_display_path(resolve_repo_path(args.reduced_manifest))}"
    )


def run_self_test() -> None:
    sequences = [["a"], ["a", "b"], ["b"]]
    observed = average_pairwise_jaccard(sequences)
    if not math.isclose(observed, 2.0 / 3.0, abs_tol=1e-12):
        raise AssertionError(f"Jaccard self-test failed: {observed}")
    entropy, occurrences, unique_values = shannon_entropy(sequences)
    if not math.isclose(entropy, 1.0, abs_tol=1e-12):
        raise AssertionError(f"Entropy self-test failed: {entropy}")
    if occurrences != 4 or unique_values != 2:
        raise AssertionError("Entropy count self-test failed")
    print("Generation diversity self-test passed.")


def main() -> None:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return

    manifest = resolve_repo_path(args.reduced_manifest)
    out_csv = resolve_repo_path(args.out_csv)
    out_json = resolve_repo_path(args.out_json)
    out_tex = resolve_repo_path(args.out_tex)
    records, source = read_full_records(args)
    reduced_ids, manifest_hash = read_reduced_ids(manifest)
    by_id = {str(record.get("playbook_id")): record for record in records}
    if len(by_id) != len(records):
        raise ValueError("The unreduced JSONL contains duplicate playbook IDs")
    missing_ids = sorted(reduced_ids - by_id.keys())
    if missing_ids:
        raise ValueError(
            f"Reduced manifest references {len(missing_ids)} missing playbook IDs"
        )
    reduced_records = [by_id[playbook_id] for playbook_id in sorted(reduced_ids)]

    if len(records) != args.expected_full_count:
        raise ValueError(
            f"Expected {args.expected_full_count} unreduced playbooks, found {len(records)}"
        )
    if len(reduced_records) != args.expected_reduced_count:
        raise ValueError(
            f"Expected {args.expected_reduced_count} retained playbooks, "
            f"found {len(reduced_records)}"
        )

    corpora = {
        "full_k03": analyze_corpus("Unreduced K=3 corpus", records),
        "corrected_k03_reduced": analyze_corpus(
            "Retained K=3 repository", reduced_records
        ),
    }
    for corpus in corpora.values():
        if corpus["skipped_incident_steps"]:
            raise ValueError(
                "At least one incident step lacks a required diversity field"
            )

    write_csv(out_csv, corpora)
    write_tikz(out_tex, corpora["corrected_k03_reduced"])
    payload = {
        "analysis_version": "1.1",
        "command": canonical_command(args),
        "definitions": {
            "pairwise_jaccard_distance": (
                "For each metric, convert every playbook's observations to a set; "
                "compute 1-|A intersection B|/|A union B| for every unordered "
                "playbook pair; report the arithmetic mean. Empty-empty distance is 0."
            ),
            "shannon_entropy_bits": (
                "Flatten all occurrence-level observations for a metric and compute "
                "-sum_x p(x) log2 p(x)."
            ),
        },
        "inputs": {
            "unreduced_k03_jsonl": source,
            "reduced_manifest": {
                "path": repo_display_path(manifest),
                "sha256": manifest_hash,
            },
            "incident_seed": 1337,
            "countermeasure_k": 3,
        },
        "outputs": {
            "csv": repo_display_path(out_csv),
            "tikz": repo_display_path(out_tex),
        },
        "corpora": corpora,
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    figure_metadata = {
        "artifact": repo_display_path(out_tex),
        "artifact_sha256": sha256_file(out_tex),
        "corpus": "corrected_k03_reduced",
        "playbooks": len(reduced_records),
        "source_csv": repo_display_path(out_csv),
        "source_csv_sha256": sha256_file(out_csv),
        "source_json": repo_display_path(out_json),
        "source_json_sha256": sha256_file(out_json),
        "unreduced_jsonl_sha256": source["sha256"],
        "reduced_manifest_sha256": manifest_hash,
        "command": canonical_command(args),
    }
    metadata_path = out_tex.with_suffix(out_tex.suffix + ".metadata.json")
    metadata_path.write_text(
        json.dumps(figure_metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {out_csv}")
    print(f"Wrote {out_json}")
    print(f"Wrote {out_tex}")
    print(f"Wrote {metadata_path}")


if __name__ == "__main__":
    main()
