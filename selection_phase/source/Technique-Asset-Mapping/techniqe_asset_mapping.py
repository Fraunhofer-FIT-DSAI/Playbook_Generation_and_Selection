import json
import os, re
from rdflib import Graph, Namespace, URIRef
from SPARQLWrapper import SPARQLWrapper, JSON

"""
This script extracts Mitre assets for MITRE ATT&CK techniques and saves results in owl file.
"""

# === SPARQL connection to GraphDB ===
sparql = SPARQLWrapper(os.getenv("GRAPHDB_URL", "http://localhost:7200/repositories/incident-response"))
sparql.setReturnFormat(JSON)

# Query: Get all subclasses of OffensiveTechnique with labels
sparql.setQuery("""
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?technique ?label
WHERE {
  ?technique rdfs:subClassOf+ d3f:OffensiveTechnique .
  ?technique rdfs:label ?label .
}
ORDER BY ?label
""")

results = sparql.query().convert()

# Build mapping: label → URI
label_to_iri = {}
for result in results["results"]["bindings"]:
    label = result["label"]["value"].strip()
    uri = result["technique"]["value"]
    label_to_iri[label] = URIRef(uri)

print(f" Retrieved {len(label_to_iri)} offensive techniques from GraphDB.")


# Load the MITRE ICS ATT&CK JSON (replace with your path)
with open("Technique-Asset-Mapping/ics-attack.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# Build lookup dictionaries
techniques = {}
assets = {}

for obj in data["objects"]:
    if obj.get("type") == "attack-pattern":
        techniques[obj["id"]] = obj.get("name", "").strip()
    elif obj.get("type") == "x-mitre-asset":
        assets[obj["id"]] = obj.get("name", "").strip()

# Extract technique-to-asset mappings using relationships
technique_to_assets = {}
for obj in data["objects"]:
    if obj.get("type") == "relationship" and obj.get("relationship_type") == "targets":
        src = obj.get("source_ref")
        tgt = obj.get("target_ref")

        if src in techniques and tgt in assets:
            technique_label = techniques[src]
            asset_name = assets[tgt]
            technique_to_assets.setdefault(technique_label, set()).add(asset_name)
            


# Build lookup: technique label or external ID → all external IDs
technique_label_to_external_ids = {}

for obj in data["objects"]:
    if obj.get("type") != "attack-pattern":
        continue

    name = obj.get("name", "").strip()
    refs = obj.get("external_references", [])
    external_ids = set()

    for ref in refs:
        if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
            external_ids.add(ref["external_id"])

        url = ref.get("url", "")
        match = re.search(r"/techniques/(T\d{4,5})", url)
        if match:
            external_ids.add(match.group(1))

    # Store mapping by name and each external_id
    for label in [name] + list(external_ids):
        technique_label_to_external_ids[label] = external_ids





# Output file
output_file = "Technique-Asset-Mapping//technique_asset_mapping.owl"
if os.path.exists(output_file):
    os.remove(output_file)

# Define RDF Graph and Namespace
g = Graph()
IRSO = Namespace("http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#")
D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

g.bind("irso", IRSO)
g.bind("d3f", D3F)

# Add triples for each technique-asset mapping
not_found = []

for technique_label, asset_names in technique_to_assets.items():
    tech_uri = label_to_iri.get(technique_label)
    
    if not tech_uri:
        not_found.append(technique_label)
        continue

    for asset in asset_names:
        asset_uri = URIRef(IRSO + asset.replace("(", "").replace(")", "").replace(" ", "_")) # paranteses can break protege
        g.add((asset_uri, IRSO.isTargetedBy, tech_uri))
        
        external_ids = technique_label_to_external_ids.get(technique_label, set())
        for ext_id in external_ids:
            ext_uri = URIRef(D3F + ext_id)
            g.add((asset_uri, IRSO.isTargetedBy, ext_uri))

# Serialize OWL file
g.serialize(destination=output_file, format="xml")
print(f"\n OWL file written to: {output_file}")
#if not_found:
    #print(f" The following techniques could not be resolved in your ontology:")
    #for label in not_found:
        #print(f"   - {label}")
