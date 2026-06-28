#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from closed_loop_common import repo_path

requests = None


CONTENT_TYPES = {
    ".owl": "application/rdf+xml",
    ".rdf": "application/rdf+xml",
    ".xml": "application/rdf+xml",
    ".ttl": "text/turtle",
    ".nt": "application/n-triples",
    ".jsonld": "application/ld+json",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Load RDF files into a local GraphDB/RDF4J repository."
    )
    parser.add_argument(
        "--graphdb-base",
        default="http://localhost:7200",
        help="GraphDB base URL, without /repositories.",
    )
    parser.add_argument(
        "--repo",
        default="incident-response",
        help="Repository ID.",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Delete all statements in the repository before importing files.",
    )
    parser.add_argument("files", nargs="+", type=Path, help="RDF files to import.")
    return parser.parse_args()


def require_requests() -> None:
    global requests
    if requests is None:
        try:
            import requests as requests_module
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Missing dependency: requests. Install dependencies with `pip install -r requirements.txt`."
            ) from exc
        requests = requests_module
    if requests is None:
        raise RuntimeError("Missing dependency: requests. Install dependencies with `pip install -r requirements.txt`.")


def statements_url(base: str, repo: str) -> str:
    return base.rstrip("/") + f"/repositories/{repo}/statements"


def main() -> None:
    args = parse_args()
    require_requests()
    url = statements_url(args.graphdb_base, args.repo)

    if args.clear:
        response = requests.delete(url, timeout=60)
        response.raise_for_status()
        print(f"Cleared repository {args.repo}")

    for raw_path in args.files:
        path = repo_path(raw_path)
        if not path.exists():
            raise FileNotFoundError(path)
        content_type = CONTENT_TYPES.get(path.suffix.lower(), "application/rdf+xml")
        with path.open("rb") as fh:
            response = requests.post(url, data=fh, headers={"Content-Type": content_type}, timeout=180)
        response.raise_for_status()
        print(f"Imported {path}")


if __name__ == "__main__":
    main()
