import pandas as pd
import os
from mitreattack.stix20 import MitreAttackData

"""
Generates Sparql queries from attack scenario descriptions.
Query finds all relevant playbooks for an attack scenario.
"""

# Load MITRE ATT&CK data
enterprise_data = MitreAttackData("Attack-CVE-Mapping/enterprise-attack.json")
ics_data = MitreAttackData("Attack-CVE-Mapping/ics-attack.json")

# Build name-to-ID map from both datasets
technique_name_to_ids = {}

def add_techniques(data_source):
    for obj in data_source.get_techniques(include_subtechniques=True):
        stix_id = obj["id"]
        attack_id = data_source.get_attack_id(stix_id)
        name = data_source.get_name(stix_id).lower().strip()
        technique_name_to_ids.setdefault(name, set()).add(attack_id)

add_techniques(enterprise_data)
add_techniques(ics_data)

# Paths
scenario_folder = "Use-Case/SparqlQueryGeneration/LIAO-NO ICS main SCENARIO"
output_folder = "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES"
os.makedirs(output_folder, exist_ok=True)

# Process each CSV in the folder
for file in os.listdir(scenario_folder):
    if not file.endswith(".csv"):
        continue

    file_path = os.path.join(scenario_folder, file)
    df = pd.read_csv(file_path, usecols=["TECHNIQUE"])
    technique_names = df["TECHNIQUE"].dropna().drop_duplicates().str.lower().str.strip()

    uris = set()
    matched_techniques = set()
    
    for tech in technique_names:
        ids = technique_name_to_ids.get(tech)
        if ids:
            matched_techniques.add(tech)
            for attack_id in ids:
                uris.add(f"http://d3fend.mitre.org/ontologies/d3fend.owl#{attack_id}")
                
        # Print coverage to console
    total = len(technique_names)
    matched = len(matched_techniques)
    coverage = (matched / total * 100) if total > 0 else 0
    print(f"{file.replace('.csv', '')}: Matched {matched}/{total} techniques ({coverage:.2f}%)")

    # Create SPARQL query
    sparql_query = """
PREFIX irso: <http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#>
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?stepID ?playbookID ?attackId ?defenseRelationship ?artifact
WHERE {
  VALUES ?attackId {
"""

    for uri in sorted(uris):
        sparql_query += f"    <{uri}>\n"

    sparql_query += """  }

  {
    # Retrieve artifacts through direct relationships
    ?attackId ?artifactRelationship ?artifact .
    ?artifactRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
  }
  UNION
  {
    # Retrieve artifacts through inherited relationships
    ?attackId rdfs:subClassOf+ ?ancestor .
    ?ancestor ?inheritedArtifactRelationship ?artifact .
    ?inheritedArtifactRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
  }

  # Retrieve artifact labels
  ?artifact rdfs:label ?artifactLabel .

  # Find defensive techniques for these artifacts
  ?defensiveTechnique ?defenseRelationship ?artifact .
  ?defenseRelationship rdfs:subPropertyOf d3f:may-be-associated-with .

  # Retrieve defensive technique labels
  ?defensiveTechnique rdfs:label ?defensiveTechniqueLabel .
  ?defensiveTechnique rdf:type d3f:DefensiveTechnique .
    
  # Find playbook steps that use these defensive techniques
  ?step irso:usesDefensiveTechnique ?defensiveTechnique .

  # Find the playbook that contains this step
  ?playbook irso:hasStep ?step .
    
  # Find stepID  
  ?step irso:hasStepID ?stepID .
  
  #Find playbook ID
  ?playbook irso:hasPlaybookID ?playbookID .

}
ORDER BY ?playbookID

"""

    # Write output
    output_path = os.path.join(output_folder, f"{file.replace('.csv', '')}.sparql")
    with open(output_path, "w", encoding="utf-8") as sparql_file:
        sparql_file.write(sparql_query)
        
        

