import pandas as pd
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
from rdflib import Graph, Namespace, URIRef

""" Generates owl file for the mapping between playbook steps and defend mechanisms """

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_fragment(value):
    text = "" if pd.isna(value) else str(value).strip()
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or ""


csv_file_path = PROJECT_ROOT / "Playbook-defend-mapping" / "MainPart" / "playbook_defend_mapping.csv"
df = pd.read_csv(csv_file_path)

IRSO = Namespace("http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#")
D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#") 

g = Graph()
g.bind("irso", IRSO)
g.bind("d3f", D3F)  

for _, row in df.iterrows():
    step_id = safe_fragment(row["Step ID"])
    technique_id = safe_fragment(row["Best Matched D3FEND Technique"])

    if not step_id or not technique_id or technique_id.lower() in {"nan", "no_match", "no-match"}:
        continue

    step_uri = URIRef(IRSO + "Step_" + step_id)
    defensive_technique_uri = URIRef(D3F + technique_id)

    g.add((step_uri, IRSO.usesDefensiveTechnique, defensive_technique_uri))  

output_file = PROJECT_ROOT / "GraphDB" / "playbook_step_defend_mapping.owl"
output_file.parent.mkdir(parents=True, exist_ok=True)
g.serialize(destination=output_file, format="xml")

manifest_path = PROJECT_ROOT / "Playbook-defend-mapping" / "MainPart" / "semantic_mapping_manifest.json"
if manifest_path.exists():
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    repo_root = PROJECT_ROOT.parents[1]
    manifest["owl_build"] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "mapping_csv_sha256": file_sha256(csv_file_path),
        "link_count": sum(
            1 for _ in g.triples((None, IRSO.usesDefensiveTechnique, None))
        ),
        "triple_count": len(g),
        "output_sha256": {
            str(output_file.relative_to(repo_root)): file_sha256(output_file)
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
else:
    print(f"WARNING: mapping provenance manifest is missing: {manifest_path}")

print(f"Wrote {len(g)} step-to-D3FEND links to {output_file}")
