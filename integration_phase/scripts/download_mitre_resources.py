#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

from closed_loop_common import repo_path, write_json


DEFAULT_ATTACK_TAG = "ATT&CK-v19.1"
DEFAULT_D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.owl"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download official MITRE ATT&CK STIX and D3FEND resources used by the full workflow."
    )
    parser.add_argument(
        "--attack-tag",
        default=DEFAULT_ATTACK_TAG,
        help="MITRE CTI Git tag to fetch, for example ATT&CK-v19.1.",
    )
    parser.add_argument(
        "--d3fend-url",
        default=DEFAULT_D3FEND_URL,
        help="D3FEND ontology URL.",
    )
    parser.add_argument("--include-mobile", action="store_true")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("data/external_resource_manifest.json"),
    )
    return parser.parse_args()


def attack_url(tag: str, domain: str) -> str:
    encoded_tag = quote(tag, safe="")
    filename = f"{domain}.json"
    return f"https://raw.githubusercontent.com/mitre/cti/{encoded_tag}/{domain}/{filename}"


def download(url: str, destination: Path, force: bool) -> dict[str, str]:
    destination = repo_path(destination)
    assert destination is not None
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not force:
        return {"url": url, "path": str(destination), "status": "exists"}
    with urlopen(url, timeout=120) as response:
        data = response.read()
    destination.write_bytes(data)
    return {"url": url, "path": str(destination), "status": "downloaded", "bytes": str(len(data))}


def main() -> None:
    args = parse_args()
    resources: list[tuple[str, Path]] = [
        (
            attack_url(args.attack_tag, "enterprise-attack"),
            Path("selection_phase/source/Attack-CVE-Mapping/enterprise-attack.json"),
        ),
        (
            attack_url(args.attack_tag, "ics-attack"),
            Path("selection_phase/source/Attack-CVE-Mapping/ics-attack.json"),
        ),
        (
            attack_url(args.attack_tag, "ics-attack"),
            Path("selection_phase/source/Technique-Asset-Mapping/ics-attack.json"),
        ),
        (
            args.d3fend_url,
            Path("selection_phase/source/GraphDB/d3fend.owl"),
        ),
        (
            args.d3fend_url,
            Path("selection_phase/source/Playbook-defend-mapping/Preprocessing/d3fend.owl"),
        ),
        (
            args.d3fend_url,
            Path("generation_phase/source/Response_generation/def3nd/d3fend.owl"),
        ),
    ]
    if args.include_mobile:
        resources.append((
            attack_url(args.attack_tag, "mobile-attack"),
            Path("selection_phase/source/Attack-CVE-Mapping/mobile-attack.json"),
        ))

    records = [download(url, destination, args.force) for url, destination in resources]
    manifest = {
        "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
        "attack_tag": args.attack_tag,
        "d3fend_url": args.d3fend_url,
        "resources": records,
        "notice": "MITRE ATT&CK and MITRE D3FEND remain third-party resources. Preserve their notices and terms when redistributing.",
    }
    write_json(repo_path(args.manifest), manifest)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
