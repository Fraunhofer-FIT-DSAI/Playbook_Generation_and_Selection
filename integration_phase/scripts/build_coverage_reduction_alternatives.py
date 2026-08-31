#!/usr/bin/env python3
"""Build two pre-defined ATT&CK-coverage-aware reduction ablations."""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from closed_loop_common import (
    join_multi,
    read_csv_dicts,
    repo_display_path,
    repo_path,
    write_csv,
)
from reduce_generated_playbooks import (
    aggregate_manifest,
    diverse_representatives,
    ranking_sort_key,
    reduce_items,
    scenario_key,
    write_reduced_owl,
)


STRATEGIES = ("coverage-preserving", "marginal-coverage")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--owl", type=Path, required=True)
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=Path("data/scenario_profiles"),
    )
    parser.add_argument("--per-scenario", type=int, default=50)
    parser.add_argument(
        "--out-root",
        type=Path,
        default=Path("results/evaluation/corrected/reduction_alternatives"),
    )
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_target_attacks(profile_dir: Path) -> dict[str, set[str]]:
    index = json.loads((profile_dir / "index.json").read_text(encoding="utf-8"))
    targets: dict[str, set[str]] = {}
    for item in index.get("profiles", []):
        scenario_id = str(item.get("scenario_id", "")).strip()
        profile_path = repo_path(item.get("path", ""))
        if not scenario_id or profile_path is None or not profile_path.exists():
            continue
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        targets[scenario_id] = {
            str(value).strip()
            for value in profile.get("selection_input", {}).get("attack_ids", [])
            if str(value).strip()
        }
    return targets


def item_coverage(item: dict[str, Any], target: set[str]) -> set[str]:
    return set(item["attack_techniques"]) & target


def greedy_missing_additions(
    items: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    target_union: set[str],
    *,
    maximum: int | None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    selected_ids = {item["playbook_id"] for item in selected}
    covered = set().union(
        *(set(item["attack_techniques"]) & target_union for item in selected)
    ) if selected else set()
    reasons = {item["playbook_id"]: "canonical_hybrid" for item in selected}
    while covered != target_union:
        if maximum is not None and len(selected) >= maximum:
            break
        candidates = [
            item for item in items if item["playbook_id"] not in selected_ids
        ]
        if not candidates:
            break
        best = min(
            candidates,
            key=lambda item: (
                -len((set(item["attack_techniques"]) & target_union) - covered),
                *ranking_sort_key(item),
            ),
        )
        gain = (set(best["attack_techniques"]) & target_union) - covered
        if not gain:
            break
        selected.append(best)
        selected_ids.add(best["playbook_id"])
        covered |= gain
        reasons[best["playbook_id"]] = "protected_missing_coverage"
    return selected, reasons


def coverage_preserving(
    items: list[dict[str, Any]],
    target_union: set[str],
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    primary = list(reduce_items(items, "hybrid", limit))
    # Preserve the canonical result and add deterministic representatives only
    # for target techniques that it does not cover.
    return greedy_missing_additions(
        items,
        primary,
        target_union,
        maximum=None,
    )


def marginal_coverage(
    items: list[dict[str, Any]],
    target_union: set[str],
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    covered: set[str] = set()
    reasons: dict[str, str] = {}

    while len(selected) < limit and covered != target_union:
        candidates = [
            item for item in items if item["playbook_id"] not in selected_ids
        ]
        if not candidates:
            break
        best = min(
            candidates,
            key=lambda item: (
                -len((set(item["attack_techniques"]) & target_union) - covered),
                *ranking_sort_key(item),
            ),
        )
        gain = (set(best["attack_techniques"]) & target_union) - covered
        if not gain:
            break
        selected.append(best)
        selected_ids.add(best["playbook_id"])
        covered |= gain
        reasons[best["playbook_id"]] = "positive_marginal_coverage"

    # Fill the declared cap using the existing exact-signature representatives
    # and canonical risk/coverage/action ordering. If fewer than the cap remain
    # after signature de-duplication, continue in the same ordering over all rows.
    fill_order = sorted(diverse_representatives(items), key=ranking_sort_key)
    fill_order.extend(sorted(items, key=ranking_sort_key))
    for item in fill_order:
        if len(selected) >= limit:
            break
        if item["playbook_id"] in selected_ids:
            continue
        selected.append(item)
        selected_ids.add(item["playbook_id"])
        reasons[item["playbook_id"]] = "canonical_rank_fill"
    return selected, reasons


def build_strategy(
    *,
    strategy: str,
    rows: list[dict[str, str]],
    playbooks: dict[str, dict[str, Any]],
    input_owl: Path,
    targets: dict[str, set[str]],
    limit: int,
    output_dir: Path,
) -> dict[str, Any]:
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in playbooks.values():
        by_scenario[scenario_key(item)].append(item)

    selected_ids: set[str] = set()
    report_rows: list[dict[str, Any]] = []
    scenario_summary: dict[str, Any] = {}
    for scenario, items in sorted(by_scenario.items()):
        target = targets.get(scenario, set())
        full_union = set().union(
            *(item_coverage(item, target) for item in items)
        ) if items else set()
        if strategy == "coverage-preserving":
            selected, reasons = coverage_preserving(items, full_union, limit)
        elif strategy == "marginal-coverage":
            selected, reasons = marginal_coverage(items, full_union, limit)
        else:  # pragma: no cover - protected by STRATEGIES
            raise ValueError(strategy)
        scenario_ids = {item["playbook_id"] for item in selected}
        selected_ids |= scenario_ids
        retained_union = set().union(
            *(item_coverage(item, target) for item in selected)
        ) if selected else set()
        scenario_summary[scenario] = {
            "generated_playbooks": len(items),
            "retained_playbooks": len(selected),
            "target_attack_count": len(target),
            "generated_target_union_count": len(full_union),
            "retained_target_union_count": len(retained_union),
            "lost_target_attacks": sorted(full_union - retained_union),
            "cap": limit,
            "cap_exceeded_for_protected_coverage": len(selected) > limit,
        }
        for rank, item in enumerate(sorted(items, key=ranking_sort_key), start=1):
            report_rows.append(
                {
                    "strategy": strategy,
                    "source_scenario_id": scenario,
                    "playbook_id": item["playbook_id"],
                    "kept": str(item["playbook_id"] in scenario_ids),
                    "selection_reason": reasons.get(item["playbook_id"], ""),
                    "canonical_rank": rank,
                    "target_attack_techniques": join_multi(
                        item_coverage(item, target)
                    ),
                    "target_attack_count": len(item_coverage(item, target)),
                    "risk_reduction_pct": f"{float(item['risk_reduction']):.12f}",
                    "artifact_count": len(item["artifacts"]),
                    "phase_completeness": f"{float(item['phase_completeness']):.12f}",
                    "action_count": item["action_count"],
                }
            )

    manifest_rows = [
        row
        for row in rows
        if row.get("playbook_id", "").strip() in selected_ids
    ]
    manifest_path = output_dir / "reduced_generated_playbooks_manifest.csv"
    owl_path = output_dir / "reduced_generated_playbooks.owl"
    report_path = output_dir / "reduction_report.csv"
    summary_path = output_dir / "reduction_summary.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(manifest_path, manifest_rows, list(rows[0]) if rows else [])
    write_reduced_owl(input_owl, owl_path, selected_ids)
    write_csv(
        report_path,
        report_rows,
        [
            "strategy",
            "source_scenario_id",
            "playbook_id",
            "kept",
            "selection_reason",
            "canonical_rank",
            "target_attack_techniques",
            "target_attack_count",
            "risk_reduction_pct",
            "artifact_count",
            "phase_completeness",
            "action_count",
        ],
    )
    summary = {
        "artifact_status": "paper reduction ablation",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "strategy": strategy,
        "per_scenario_cap": limit,
        "retained_playbooks": len(selected_ids),
        "retained_manifest_rows": len(manifest_rows),
        "scenario_summary": scenario_summary,
        "coverage_preserved_in_all_scenarios": all(
            not item["lost_target_attacks"] for item in scenario_summary.values()
        ),
        "tie_policy": (
            "largest positive marginal target ATT&CK gain, then canonical "
            "risk/coverage/phase/action order, then lexicographic playbook_id"
        ),
        "outputs": {
            repo_display_path(manifest_path): file_sha256(manifest_path),
            repo_display_path(owl_path): file_sha256(owl_path),
            repo_display_path(report_path): file_sha256(report_path),
        },
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> None:
    args = parse_args()
    if args.per_scenario < 1:
        raise ValueError("--per-scenario must be positive")
    manifest = repo_path(args.manifest)
    input_owl = repo_path(args.owl)
    profile_dir = repo_path(args.profile_dir)
    out_root = repo_path(args.out_root)
    rows = read_csv_dicts(manifest)
    playbooks = aggregate_manifest(rows)
    targets = load_target_attacks(profile_dir)

    summaries = {}
    for strategy in STRATEGIES:
        output_dir = out_root / strategy.replace("-", "_")
        summaries[strategy] = build_strategy(
            strategy=strategy,
            rows=rows,
            playbooks=playbooks,
            input_owl=input_owl,
            targets=targets,
            limit=args.per_scenario,
            output_dir=output_dir,
        )

    manifest_path = out_root / "alternative_reduction_manifest.json"
    payload = {
        "artifact_status": "paper reduction ablations",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python " + shlex.join(sys.argv),
        "input_manifest": {
            "path": repo_display_path(manifest),
            "sha256": file_sha256(manifest),
        },
        "input_owl": {
            "path": repo_display_path(input_owl),
            "sha256": file_sha256(input_owl),
        },
        "profile_dir": repo_display_path(profile_dir),
        "per_scenario_cap": args.per_scenario,
        "strategies": summaries,
        "scope_boundary": (
            "Separate pre-defined ablations. The canonical corrected K=3 reducer "
            "and primary selection outputs are not replaced."
        ),
    }
    out_root.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote reduction alternatives to {out_root}")


if __name__ == "__main__":
    main()
