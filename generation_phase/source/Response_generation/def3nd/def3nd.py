import rdflib

def get_results_by_attack_and_tactic(owl_path, attack_id, tactic_class_name):
    g = rdflib.Graph()
    g.parse(owl_path, format="xml")

    NS = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
    attack_uri = rdflib.URIRef(NS + attack_id)
    tactic_uri = rdflib.URIRef(NS + tactic_class_name)

    # Step 1: Get artifacts associated with this attack
    artifact_query = f"""
    SELECT DISTINCT ?artifact WHERE {{
        <{attack_uri}> rdfs:subClassOf ?restriction .
        ?restriction owl:onProperty ?p ;
                     owl:someValuesFrom ?artifact .
    }}
    """
    artifacts = set()
    for row in g.query(artifact_query, initNs={"rdfs": rdflib.RDFS, "owl": rdflib.OWL}):
        artifact = row[0]
        name = artifact.split("#")[-1]
        if not name.startswith("TA"):  # exclude attack tactics
            artifacts.add(artifact)

   # Step 2: Get all subclasses (techniques) of the given tactic
    # AND that relate to the artifacts associated with the given ATT&CK technique

    techniques_under_tactic = set()

    for artifact_uri in artifacts:
        subclass_query = f"""
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX owl: <http://www.w3.org/2002/07/owl#>

        SELECT DISTINCT ?technique WHERE {{
            ?technique rdfs:subClassOf+ <{tactic_uri}> .
            ?technique rdfs:subClassOf ?restriction .
            ?restriction owl:onProperty ?property ;
                        owl:someValuesFrom <{artifact_uri}> .
        }}
        """
        for row in g.query(subclass_query, initNs={"rdfs": rdflib.RDFS, "owl": rdflib.OWL}):
            techniques_under_tactic.add(row[0])

    final_result = []

    for artifact_uri in artifacts:
        artifact_name = artifact_uri.split("#")[-1]

        usage_query = f"""
        SELECT DISTINCT ?class ?property WHERE {{
            ?class rdfs:subClassOf ?restriction .
            ?restriction owl:onProperty ?property ;
                         owl:someValuesFrom <{artifact_uri}> .
        }}
        """

        for row in g.query(usage_query, initNs={"rdfs": rdflib.RDFS, "owl": rdflib.OWL}):
            class_uri, prop_uri = row
            if class_uri not in techniques_under_tactic:
                continue
            technique_name = class_uri.split("#")[-1]
            relationship_name = prop_uri.split("#")[-1]

            print(technique_name)
            print(relationship_name)

            final_result.append((technique_name, relationship_name, artifact_name))

    return final_result



from rdflib import Graph, Namespace, URIRef
from rdflib.namespace import RDFS

def get_root_defensive_technique(technique_uri):
    # Load ontology
    g = Graph()
    g.parse("Response_generation/def3nd/d3fend.owl", format='xml')

    D3FEND = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
    technique = URIRef(technique_uri)

    current = technique
    visited = set()

    while True:
        if current in visited:
            break  # avoid cycles
        visited.add(current)

        parents = list(g.objects(current, RDFS.subClassOf))
        if not parents:
            break

        for parent in parents:
            # Skip restrictions
            if isinstance(parent, URIRef):
                if (parent, RDFS.subClassOf, D3FEND.DefensiveTechnique) in g:
                    return parent.split("#")[-1]
                current = parent
                break
        else:
            break

    return current.split("#")[-1]  # fallback if no root found

# Example usage
technique_uri = "http://d3fend.mitre.org/ontologies/d3fend.owl#ActiveCertificateAnalysis"
root = get_root_defensive_technique(technique_uri)
