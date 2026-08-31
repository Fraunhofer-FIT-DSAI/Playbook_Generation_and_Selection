#!/usr/bin/env python3
"""Project the paper's community corpus into the SBERT input schema."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


SOURCE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SOURCE_ROOT.parents[1]
DEFAULT_SOURCE = SOURCE_ROOT / "Playbook" / "steps-coded.csv"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "filtered_playbooks.csv"
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "community_preprocessing_manifest.json"
PAPER_VENDORS = ["FortiSOAR", "Rapid7", "XSOAR"]
SELECTED_COLUMNS = [
    "playbook_name",
    "playbook_id",
    "playbook_description",
    "step_names",
    "step_id",
    "step_description",
    "action",
    "artifact",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--vendor",
        action="append",
        help=(
            "Exact vendor allowlist; repeat for multiple vendors. If omitted, use "
            "the paper corpus: FortiSOAR, Rapid7, and XSOAR."
        ),
    )
    parser.add_argument(
        "--all-vendors",
        action="store_true",
        help="Map every vendor in steps-coded.csv instead of the paper corpus.",
    )
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def main() -> None:
    args = parse_args()
    if args.vendor and args.all_vendors:
        raise ValueError("--vendor and --all-vendors are mutually exclusive")

    frame = pd.read_csv(args.source, delimiter=";")
    missing_columns = sorted((set(SELECTED_COLUMNS) | {"vendor"}) - set(frame.columns))
    if missing_columns:
        raise ValueError(f"Source corpus is missing required columns: {', '.join(missing_columns)}")

    input_rows = len(frame)
    input_playbooks = int(frame["playbook_id"].nunique())
    vendors = [] if args.all_vendors else (args.vendor or PAPER_VENDORS)
    if vendors:
        frame = frame[frame["vendor"].isin(vendors)].copy()
    filtered = frame[SELECTED_COLUMNS].copy()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    filtered.to_csv(args.output, index=False)
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": display_path(args.source),
        "source_sha256": file_sha256(args.source),
        "source_delimiter": ";",
        "input_rows": input_rows,
        "input_playbooks": input_playbooks,
        "vendor_filter": vendors,
        "vendor_filter_semantics": "exact allowlist; empty only with --all-vendors",
        "selected_columns": SELECTED_COLUMNS,
        "output": display_path(args.output),
        "output_sha256": file_sha256(args.output),
        "output_rows": len(filtered),
        "output_playbooks": int(filtered["playbook_id"].nunique()),
        "output_steps": int(filtered["step_id"].nunique()),
        "missing_values": {
            column: int(filtered[column].isna().sum())
            for column in SELECTED_COLUMNS
        },
        "row_order": "source order preserved",
    }
    args.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Extracted {len(filtered)} rows to {args.output}")
    print(f"Wrote preprocessing manifest to {args.manifest}")


if __name__ == "__main__":
    main()
