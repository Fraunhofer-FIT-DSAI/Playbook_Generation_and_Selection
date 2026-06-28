import pandas as pd
from pathlib import Path
import re
from rdflib import Graph, Namespace, URIRef

""" Generates owl file for the mapping between playbook steps and defend mechanisms """

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def safe_fragment(value):
    text = "" if pd.isna(value) else str(value).strip()
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or ""


# Load CSV file
csv_file_path = PROJECT_ROOT / "Playbook-defend-mapping" / "MainPart" / "playbook_defend_mapping.csv"
df = pd.read_csv(csv_file_path)

# Define Ontology Namespaces
IRSO = Namespace("http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#")
D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#") 

g = Graph()
g.bind("irso", IRSO)
g.bind("d3f", D3F)  

# Iterate over each row to create OWL instances
for _, row in df.iterrows():
    step_id = safe_fragment(row["Step ID"])
    technique_id = safe_fragment(row["Best Matched D3FEND Technique"])

    if not step_id or not technique_id or technique_id.lower() in {"nan", "no_match", "no-match"}:
        continue  # Skip if any data is missing

    step_uri = URIRef(IRSO + "Step_" + step_id)
    defensive_technique_uri = URIRef(D3F + technique_id)

    # Link Step to Defensive Technique
    g.add((step_uri, IRSO.usesDefensiveTechnique, defensive_technique_uri))  

# Save updated OWL File
output_file = PROJECT_ROOT / "Playbook-defend-mapping" / "MainPart" / "playbook_step_defend_mapping.owl"
g.serialize(destination=output_file, format="xml")


