import os

from SPARQLWrapper import SPARQLWrapper, JSON
""" Gets affected components for a given playbook using the ontology from GraphDB """

GRAPHDB_URL = os.getenv("GRAPHDB_URL", "http://localhost:7200/repositories/incident-response")

#execute the query from python
def execute_sparql(query, endpoint):
    """Executes a SPARQL query and returns results."""
    sparql = SPARQLWrapper(endpoint)
    sparql.setQuery(query)
    sparql.setReturnFormat(JSON)

    try:
        results = sparql.query().convert()
        #print("\n Raw SPARQL Query Results:", results["results"]["bindings"])
        return results["results"]["bindings"]
    except Exception as e:
        print("Error executing SPARQL query:", e)
        return None

# SPARQL Query to get all playbooks
sparql_query = """
PREFIX irso: <http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#>

SELECT DISTINCT ?playbookID ?component
WHERE {
  ?playbook irso:hasStep ?step .
  ?step irso:affectsSCADAComponent  ?component .
  ?playbook irso:hasPlaybookID ?playbookID .
}
ORDER BY ?playbookID
"""

results = execute_sparql(sparql_query, GRAPHDB_URL)

# Process Results
playbook_component_mapping = {}

if results:
    for row in results:
        playbook_id = row["playbookID"]["value"]
        component_iri = row["component"]["value"]
        component_name = component_iri.split("#")[-1]  #  Extract only the name after '#'

        if playbook_id not in playbook_component_mapping:
            playbook_component_mapping[playbook_id] = []

        playbook_component_mapping[playbook_id].append(component_name)  

#print("Loaded Playbook-Step-Component Relationships:", playbook_steps)
