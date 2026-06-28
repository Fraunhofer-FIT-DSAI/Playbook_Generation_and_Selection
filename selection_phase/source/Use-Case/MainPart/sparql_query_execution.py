from SPARQLWrapper import SPARQLWrapper, JSON
from collections import Counter, defaultdict
import os
import re

""" It provides functions to query a GraphDB and evaluate how well cybersecurity playbooks cover attack techniques, defenses, assets, and artifacts for different scenarios. """


# GraphDB SPARQL Endpoint
GRAPHDB_URL = os.getenv("GRAPHDB_URL", "http://localhost:7200/repositories/incident-response")
def read_sparql_query(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()

def execute_sparql(query, endpoint):
    sparql = SPARQLWrapper(endpoint)
    sparql.setQuery(query)
    sparql.setReturnFormat(JSON)
    try:
        results = sparql.query().convert()
        return results["results"]["bindings"]
    except Exception as e:
        raise RuntimeError(f"Error executing SPARQL query against {endpoint}: {e}") from e


def scenario_values_block(sparql_query):
    pattern = r'VALUES\s+\?attackId\s*\{(.*?)\}'
    match = re.search(pattern, sparql_query, re.DOTALL)
    if not match:
        return ""
    return match.group(1).strip()


def build_scenario_universe_query(sparql_query):
    values_block = scenario_values_block(sparql_query)
    if not values_block:
        return ""
    return f"""
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

    SELECT DISTINCT ?attackId ?defenseRelationship ?artifact
    WHERE {{
      VALUES ?attackId {{
        {values_block}
      }}

      {{
        ?attackId ?artifactRelationship ?artifact .
        ?artifactRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
      }}
      UNION
      {{
        ?attackId rdfs:subClassOf+ ?ancestor .
        ?ancestor ?inheritedArtifactRelationship ?artifact .
        ?inheritedArtifactRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
      }}

      ?artifact rdfs:label ?artifactLabel .
      ?defensiveTechnique ?defenseRelationship ?artifact .
      ?defenseRelationship rdfs:subPropertyOf d3f:may-be-associated-with .
      ?defensiveTechnique rdf:type d3f:DefensiveTechnique .
    }}
    """


def get_scenario_universe_rows(sparql_query_file):
    sparql_query = read_sparql_query(sparql_query_file)
    universe_query = build_scenario_universe_query(sparql_query)
    if not universe_query:
        return []
    return execute_sparql(universe_query, GRAPHDB_URL)

def get_all_playbooks(sparql_query_file):
    sparql_query = read_sparql_query(sparql_query_file)
    results = execute_sparql(sparql_query, GRAPHDB_URL)

    all_playbooks = []
    playbook_counter = Counter()

    if results:
        for row in results:
            playbook = row["playbookID"]["value"]
            all_playbooks.append(playbook)   
            playbook_counter[playbook] += 1

    all_playbooks_list = list(set(all_playbooks))

    best_relevant_playbooks = []
    if playbook_counter:
        max_count = max(playbook_counter.values())
        best_relevant_playbooks = [pb for pb, count in playbook_counter.items() if count == max_count]

    #print("\n All Playbooks:", all_playbooks_list)
    #print("\n Most Frequent Playbooks:", most_common_playbooks)
    

    return all_playbooks_list, best_relevant_playbooks  # Return values dynamically


import re

def get_technique_uris_for_scenario(sparql_query_file):
    """
    Extracts all attack technique URIs used in a scenario by parsing them directly
    from the VALUES block in the SPARQL file (assumes URIs, not labels).
    Returns the list of URIs and unmatched_count = 0 (since nothing is looked up).
    """
    with open(sparql_query_file, "r", encoding="utf-8") as f:
        sparql_query = f.read()

    # Match: VALUES ?attackId { <URI> <URI> }
    pattern = r'VALUES\s+\?attackId\s*\{(.*?)\}'
    match = re.search(pattern, sparql_query, re.DOTALL)
    if not match:
        print("No VALUES block found for ?attackId")
        return [], 0

    block = match.group(1)
    uris = re.findall(r'<([^>]+)>', block)

    return sorted(set(uris)), 0




def get_technique_labels_from_uris(technique_uris):
    query_template = """
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?technique ?label
    WHERE {
        VALUES ?technique {
            %s
        }
        ?technique rdfs:label ?label .
    }
    """
    values_clause = "\n            ".join(f"<{uri}>" for uri in technique_uris)
    full_query = query_template % values_clause

    results = execute_sparql(full_query, GRAPHDB_URL)
    technique_labels = {}

    if results:
        for row in results:
            uri = row["technique"]["value"]
            label = row["label"]["value"]
            technique_id = uri.split("#")[-1]
            technique_labels[technique_id] = label

    return technique_labels



def get_attack_technique_coverage_per_playbook(sparql_query_file):
    """
    Computes how many attack techniques are mitigated by each playbook,
    based on the scenario query that returns ?attackId, ?stepID, and ?playbookID.
    """
    sparql_query = read_sparql_query(sparql_query_file)
    results = execute_sparql(sparql_query, GRAPHDB_URL)

    mitigations = {}  # playbookID → set of attack techniques

    if results:
        for row in results:
            playbook_id = row["playbookID"]["value"]
            attack_id = row["attackId"]["value"]

            if playbook_id not in mitigations:
                mitigations[playbook_id] = set()
            mitigations[playbook_id].add(attack_id)

    return mitigations


def get_all_techniques_for_playbook(playbook_id: str) -> list[str]:
    """
    Returns all attack technique IDs (with potential duplicates across steps)
    associated with the given playbook ID, filtering out non-attack resources.
    """
    sparql_query = f"""
    PREFIX irso: <http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#>
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

    SELECT ?attackId
    WHERE {{
        ?playbook irso:hasPlaybookID "{playbook_id}" .
        ?playbook irso:hasStep ?step .
        ?step irso:usesDefensiveTechnique ?defensiveTechnique .
        ?defensiveTechnique rdf:type d3f:DefensiveTechnique .

        ?defensiveTechnique ?relationship ?artifact .
        ?artifact rdfs:label ?artifactLabel .

        ?attackId d3f:produces ?artifact .

        # Include only IRI identifiers that match attack technique patterns
        FILTER STRSTARTS(STR(?attackId), STR(d3f:T))
    }}
    ORDER BY ?attackId
    """

    results = execute_sparql(sparql_query, GRAPHDB_URL)
    return [row["attackId"]["value"].split("#")[-1] for row in results] if results else []





def get_playbook_asset_coverage(scenario_assets):
    query = """
    PREFIX irso: <http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

    SELECT DISTINCT ?playbookID ?asset
    WHERE {
      ?playbook irso:hasPlaybookID ?playbookID .
      ?playbook irso:hasStep ?step .
      ?step irso:affectsSCADAComponent ?asset .
    }
    """
    results = execute_sparql(query, GRAPHDB_URL)

    playbook_assets = {}

    if results:
        for row in results:
            playbook_id = row["playbookID"]["value"]
            asset = row["asset"]["value"].split("#")[-1]
            playbook_assets.setdefault(playbook_id, set()).add(asset)


    coverage = {}
    for playbook_id, assets in playbook_assets.items():
        matched = scenario_assets.intersection(assets)
        score = len(matched) / len(scenario_assets) if scenario_assets else 0
        if score > 0:
            coverage[playbook_id] = score  # Only include relevant playbooks

    # Keep only relevant playbooks in playbook_assets too
    playbook_assets = {pb: playbook_assets[pb] for pb in coverage}

    return coverage


def get_defense_step_coverage(sparql_query_file,scenario_attack_ids):
    
    sparql_query = read_sparql_query(sparql_query_file)
    results = execute_sparql(sparql_query, GRAPHDB_URL)
    universe_results = get_scenario_universe_rows(sparql_query_file)

    used_pairs = defaultdict(set)  # (playbook, attack, rel) → stepIDs
    step_counts = defaultdict(int)
    redundancy = defaultdict(int)
    coverage = defaultdict(int)
    completeness = defaultdict(float)
    adjusted_completeness = defaultdict(float)

    defend_matrix = defaultdict(set)  # attack → applicable defense relationships

    for row in universe_results:
        attack = row["attackId"]["value"].split("#")[-1]
        rel_uri = row["defenseRelationship"]["value"]
        if "may-" not in rel_uri:
            continue
        rel = rel_uri.split("#")[-1]
        defend_matrix[attack].add(rel)

    for row in results:
        playbook = row["playbookID"]["value"]
        step = row["stepID"]["value"]
        attack = row["attackId"]["value"].split("#")[-1]
        rel_uri = row["defenseRelationship"]["value"]

        if "may-" not in rel_uri:
            continue

        rel = rel_uri.split("#")[-1]
        used_pairs[(playbook, attack, rel)].add(step)

    for (pb, atk, rel), steps in used_pairs.items():
        count = len(steps)
        step_counts[pb] += count
        coverage[pb] += 1
        if count > 1:
            redundancy[pb] += count - 1

    # Calculate max possible coverage based on scenario's applicable defenses
    max_possible = sum(len(defend_matrix[atk]) for atk in scenario_attack_ids if atk in defend_matrix)

    for pb in coverage:
        if max_possible > 0:
            completeness[pb] = coverage[pb] / max_possible
            penalty = redundancy[pb] / step_counts[pb] if step_counts[pb] > 0 else 0
            adjusted_completeness[pb] = completeness[pb] * (1 - penalty)
        else:
            completeness[pb] = 0
            adjusted_completeness[pb] = 0

    return coverage, step_counts, redundancy, completeness, adjusted_completeness


def get_artifact_coverage_per_playbook(sparql_query_file):
    """
    Computes how many scenario-relevant digital artifacts are covered by each playbook,
    based on the scenario SPARQL query that returns ?artifact and ?playbookID.
    """
    sparql_query = read_sparql_query(sparql_query_file)
    results = execute_sparql(sparql_query, GRAPHDB_URL)
    universe_results = get_scenario_universe_rows(sparql_query_file)

    artifact_coverage = {}  # playbookID → set of artifacts
    scenario_artifacts = set()

    for row in universe_results:
        artifact_uri = row.get("artifact", {}).get("value")
        if artifact_uri:
            scenario_artifacts.add(artifact_uri.split("#")[-1])

    for row in results:
        playbook_id = row["playbookID"]["value"]
        artifact_uri = row.get("artifact", {}).get("value")
        if not artifact_uri:
            continue

        artifact_id = artifact_uri.split("#")[-1]

        if playbook_id not in artifact_coverage:
            artifact_coverage[playbook_id] = set()
        artifact_coverage[playbook_id].add(artifact_id)

    return artifact_coverage, scenario_artifacts










