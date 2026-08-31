#!/usr/bin/env python3
"""Build the weak-profile diagnostic from the recorded augmented K=3 results."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = Path(
    "results/evaluation/corrected/augmented-reduced/"
    "scenario_playbook_evaluation_augmented-reduced.csv"
)
DEFAULT_MANIFEST = Path(
    "results/generated_repository/corrected_k03/"
    "reduced_generated_playbooks_manifest.csv"
)
DEFAULT_CSV = Path(
    "results/evaluation/corrected/publication_tables/"
    "corrected_weak_normalized_profiles.csv"
)
DEFAULT_TEX = Path(
    "results/evaluation/corrected/publication_figures/"
    "corrected_weak_normalized_profiles.tex"
)
DISPLAY_LABELS = {
    "Emergency Services": "Emergency services",
    "Food and Agriculture": "Food/agriculture",
    "Nuclear Reactors, Materials, and Waste": "Nuclear/materials/waste",
    "Commercial Facilities": "Commercial facilities",
    "Critical Manufacturing": "Critical manufacturing",
    "Energy": "Energy",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--requested-count", type=int, default=5)
    parser.add_argument("--out-csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out-tex", type=Path, default=DEFAULT_TEX)
    parser.add_argument("--expected-scenarios", type=int, default=16)
    parser.add_argument("--expected-repository-count", type=int, default=167)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return resolved.name


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        source_rows = list(csv.DictReader(handle))
    rows: list[dict[str, Any]] = []
    for source in source_rows:
        if source.get("Scenario") == "Average":
            continue
        combined = float(source["combined_attack_recall"])
        achievable = float(source["achievable_combined_attack_recall"])
        normalized = float(source["normalized_combined_attack_recall"])
        expected_normalized = combined / achievable if achievable > 0 else 0.0
        if combined > achievable + 1e-12:
            raise ValueError(
                f"Combined recall exceeds achievable recall for {source['Scenario']}"
            )
        if not math.isclose(normalized, expected_normalized, abs_tol=1e-9):
            raise ValueError(
                f"Normalized recall is inconsistent for {source['Scenario']}"
            )
        rows.append(
            {
                "scenario": source["Scenario"],
                "selected_playbook_id": source["Top_MCDM_Playbook"],
                "selected_source": source["candidate_source"],
                "combined_recall": combined,
                "achievable_combined_recall": achievable,
                "normalized_combined_recall": normalized,
                "absolute_headroom": achievable - combined,
                "selected_action_count": int(source["selected_action_count"]),
                "selected_risk_reduction": source["selected_risk_reduction"],
                "scoring_profile": source["scoring_profile"],
                "missing_context_policy": source["missing_context_policy"],
            }
        )
    return rows


def select_weak_profiles(
    rows: list[dict[str, Any]], requested_count: int
) -> tuple[list[dict[str, Any]], float]:
    if requested_count <= 0 or requested_count > len(rows):
        raise ValueError("requested-count must be between 1 and the scenario count")
    ordered = sorted(
        rows,
        key=lambda row: (row["normalized_combined_recall"], row["scenario"]),
    )
    cutoff = float(ordered[requested_count - 1]["normalized_combined_recall"])
    selected = [
        row
        for row in ordered
        if float(row["normalized_combined_recall"]) <= cutoff + 1e-12
    ]
    distinct_values = sorted(
        {float(row["normalized_combined_recall"]) for row in selected}
    )
    ranks = {value: index + 1 for index, value in enumerate(distinct_values)}
    for row in selected:
        row["normalized_rank"] = ranks[float(row["normalized_combined_recall"])]
    return selected, cutoff


def manifest_playbook_count(path: Path) -> int:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return len(
            {
                row["playbook_id"]
                for row in csv.DictReader(handle)
                if row.get("playbook_id")
            }
        )


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "normalized_rank",
        "scenario",
        "selected_playbook_id",
        "selected_source",
        "combined_recall",
        "achievable_combined_recall",
        "normalized_combined_recall",
        "absolute_headroom",
        "selected_action_count",
        "selected_risk_reduction",
        "scoring_profile",
        "missing_context_policy",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    **row,
                    "combined_recall": f"{row['combined_recall']:.12f}",
                    "achievable_combined_recall": (
                        f"{row['achievable_combined_recall']:.12f}"
                    ),
                    "normalized_combined_recall": (
                        f"{row['normalized_combined_recall']:.12f}"
                    ),
                    "absolute_headroom": f"{row['absolute_headroom']:.12f}",
                }
            )


def coordinates(rows: list[dict[str, Any]], field: str) -> str:
    return " ".join(
        f"({float(row[field]):.6f},{index})"
        for index, row in enumerate(rows, start=1)
    )


def write_tikz(path: Path, rows: list[dict[str, Any]]) -> None:
    y_ticks = ",".join(str(index) for index in range(1, len(rows) + 1))
    labels = ",".join(
        "{" + DISPLAY_LABELS.get(row["scenario"], row["scenario"]) + "}"
        for row in rows
    )
    combined = coordinates(rows, "combined_recall")
    achievable = coordinates(rows, "achievable_combined_recall")
    normalized = coordinates(rows, "normalized_combined_recall")
    content = rf"""\begin{{tikzpicture}}
  \definecolor{{pbblack}}{{HTML}}{{1F2933}}
  \definecolor{{pbblue}}{{HTML}}{{2F6B8A}}
  \definecolor{{pbgold}}{{HTML}}{{B38B2E}}
  \begin{{axis}}[
    xbar,
    width=0.80\linewidth,
    height=4.6cm,
    xmin=0,
    xmax=1,
    xtick={{0,0.2,0.4,0.6,0.8,1.0}},
    xlabel={{Recall}},
    ytick={{{y_ticks}}},
    yticklabels={{{labels}}},
    yticklabel style={{font=\scriptsize}},
    tick label style={{font=\scriptsize}},
    label style={{font=\small}},
    y dir=reverse,
    bar width=3.8pt,
    xmajorgrids,
    grid style={{draw=gray!25}},
    axis line style={{draw=pbblack}},
    tick style={{draw=pbblack}},
    enlarge y limits=0.09,
    legend columns=3,
    legend style={{
      draw=none,
      fill=none,
      font=\scriptsize,
      at={{(0.5,1.02)}},
      anchor=south,
      /tikz/every even column/.append style={{column sep=5pt}},
    }},
  ]
    \addplot[fill=pbblue,draw=none,area legend] coordinates {{{combined}}};
    \addlegendentry{{Combined}}

    \addplot[fill=pbgold,draw=none,area legend] coordinates {{{achievable}}};
    \addlegendentry{{Achievable}}

    \addplot[fill=pbblack,draw=none,area legend] coordinates {{{normalized}}};
    \addlegendentry{{Normalized}}
  \end{{axis}}
\end{{tikzpicture}}
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def canonical_command() -> str:
    return (
        "python integration_phase/scripts/make_weak_profile_figure.py "
        f"--input {DEFAULT_INPUT.as_posix()} "
        f"--manifest {DEFAULT_MANIFEST.as_posix()} --requested-count 5"
    )


def write_metadata(
    path: Path,
    artifact: Path,
    source: Path,
    manifest: Path,
    rows: list[dict[str, Any]],
    cutoff: float,
    requested_count: int,
    repository_count: int,
) -> None:
    payload = {
        "artifact": display_path(artifact),
        "artifact_sha256": file_sha256(artifact),
        "command": canonical_command(),
        "source": display_path(source),
        "source_sha256": file_sha256(source),
        "repository_manifest": display_path(manifest),
        "repository_manifest_sha256": file_sha256(manifest),
        "repository_count": repository_count,
        "selection_mode": "augmented-reduced",
        "scoring_profile": "closed-loop-balanced",
        "missing_context_policy": "neutral",
        "ranking_metric": "normalized_combined_attack_recall ascending",
        "requested_profile_count": requested_count,
        "fifth_order_cutoff": cutoff,
        "included_profile_count": len(rows),
        "cutoff_tie_policy": "include every profile tied at the cutoff",
        "included_scenarios": [row["scenario"] for row in rows],
        "interpretation": (
            "Achievable recall is the source-restricted candidate-pool ceiling. "
            "Normalized recall is selected combined recall divided by that ceiling."
        ),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> None:
    rows = [
        {"scenario": "A", "normalized_combined_recall": 0.1},
        {"scenario": "B", "normalized_combined_recall": 0.2},
        {"scenario": "C", "normalized_combined_recall": 0.2},
        {"scenario": "D", "normalized_combined_recall": 0.3},
    ]
    selected, cutoff = select_weak_profiles(rows, 2)
    if cutoff != 0.2 or [row["scenario"] for row in selected] != ["A", "B", "C"]:
        raise AssertionError("Cutoff-tie self-test failed")
    print("Weak-profile figure self-test passed.")


def main() -> None:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return
    source = resolve(args.input)
    manifest = resolve(args.manifest)
    out_csv = resolve(args.out_csv)
    out_tex = resolve(args.out_tex)
    rows = read_rows(source)
    if len(rows) != args.expected_scenarios:
        raise ValueError(
            f"Expected {args.expected_scenarios} scenario rows, found {len(rows)}"
        )
    if {row["scoring_profile"] for row in rows} != {"closed-loop-balanced"}:
        raise ValueError("Input rows do not all use closed-loop-balanced scoring")
    if {row["missing_context_policy"] for row in rows} != {"neutral"}:
        raise ValueError("Input rows do not all use the neutral missing-value policy")
    repository_count = manifest_playbook_count(manifest)
    if repository_count != args.expected_repository_count:
        raise ValueError(
            f"Expected {args.expected_repository_count} generated playbooks, "
            f"found {repository_count}"
        )
    weak, cutoff = select_weak_profiles(rows, args.requested_count)
    write_csv(out_csv, weak)
    write_tikz(out_tex, weak)
    write_metadata(
        out_csv.with_suffix(out_csv.suffix + ".metadata.json"),
        out_csv,
        source,
        manifest,
        weak,
        cutoff,
        args.requested_count,
        repository_count,
    )
    write_metadata(
        out_tex.with_suffix(out_tex.suffix + ".metadata.json"),
        out_tex,
        source,
        manifest,
        weak,
        cutoff,
        args.requested_count,
        repository_count,
    )
    print(f"Wrote {out_csv}")
    print(f"Wrote {out_tex}")
    print(
        f"Included {len(weak)} profiles at or below the fifth-order cutoff "
        f"{cutoff:.12f}"
    )


if __name__ == "__main__":
    main()
