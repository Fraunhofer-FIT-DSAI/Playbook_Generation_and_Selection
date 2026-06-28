import pandas as pd
from sparql_query_execution import (
    get_all_playbooks,
    get_defense_step_coverage,
    get_technique_labels_from_uris,
    get_technique_uris_for_scenario,
    get_playbook_asset_coverage,
    get_attack_technique_coverage_per_playbook,
    get_artifact_coverage_per_playbook,
    get_all_techniques_for_playbook
)
from not_used_longer.parse_scada_model import parse_dependency_model
from not_used_longer.cio_calculator import compute_cio
from not_used_longer.get_affected_components import playbook_component_mapping
from not_used_longer.cvss_mapper import map_techniques_to_cvss
import psutil, time, os, json
from pathlib import Path

process = psutil.Process()
start_time = time.time()
start_memory = process.memory_info().rss / (1024 * 1024)  # in MB
start_cpu_time = process.cpu_times().user


"""
Loads 16 different attack scenarios and identifies for each scenario
-	candidate playbooks for them using playbook-defend mapping.
-	Calculates the digital artifact coverage and defense coverage of the candidate playbooks 
-	Uses mcdm to determine which playbook has the most coverage overall
-	Saves results into scenario_playbook_evaluation.csv
-	Measures and reports performance metrics: execution time, memory usage, and CPU load.

"""

# Define all 16 available scenarios
scenarios = {
    "Chemical": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Chemical.sparql",
    "Commercial Facilities": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Commercial Facilities.sparql",
    "Communications": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Communications.sparql",
    "Critical Manufacturing": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Critical Manufacturing.sparql",
    "Dams": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Dams.sparql",
    "Defense Industrial Base": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Defense Industrial Base.sparql",
    "Emergency Services": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Emergency Services.sparql",
    "Energy": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Energy.sparql",
    "Financial Services": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Financial Services.sparql",
    "Food and Agriculture": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Food and Agriculture.sparql",
    "Government Facilities": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Government Facilities.sparql",
    "Healthcare and Public Health": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Healthcare and Public Health.sparql",
    "Information Technology": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Information Technology.sparql",
    "Nuclear Reactors, Materials, and Waste": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Nuclear Reactors, Materials, and Waste.sparql",
    "Transportation Systems": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Transportation Systems.sparql",
    "Water and Wastewater Systems": "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES/df_SCENARIO_Water and Wastewater Systems.sparql"
}


# Load SCADA dependency model
#xml_file_path = "Use-Case/SCADA.dependencymodel.xml"
#dependency_model = parse_dependency_model(xml_file_path)

# Initialize list to collect all results
all_results = []
OUTPUT_DIR = Path(os.getenv("SELECTION_OUTPUT_DIR", "out/selection"))
SCORES_DIR = OUTPUT_DIR / "mcdm_scores_per_scenario"

for scenario_name, sparql_query_file in scenarios.items():
    print(f"\nProcessing Scenario: {scenario_name}")

    # Retrieve technique URIs and unmatched count
    technique_uris, unmatched_count = get_technique_uris_for_scenario(sparql_query_file)
    if not technique_uris:
        print(f"  No techniques found for scenario: {scenario_name}")
        continue


    # Map technique URIs to labels
    technique_labels = get_technique_labels_from_uris(technique_uris)
    #print(f" Techniqe labels are: {technique_labels}")
    if not technique_labels:
        print(f"  No technique labels found for scenario: {scenario_name}")
        continue

    # Map techniques to CVSS scores
    #cvss_info = map_techniques_to_cvss(
    #    technique_labels,
    #    "Attack-CVE-Mapping/merged_attack_capec_mapping_with_cvss.csv"
    #)
    #print(cvss_info)
    
    
    


    # Retrieve playbooks and best relevant playbooks
    all_playbooks, best_relevant_playbooks = get_all_playbooks(sparql_query_file)
    if not all_playbooks:
        print(f"  No playbooks found for scenario: {scenario_name}")
        continue

    # Extract scenario technique IDs
    scenario_technique_ids = set(technique_labels.keys())
    #print(scenario_technique_ids)

    # Load semantic mapping CSV
    #match_df = pd.read_csv("Techniqe-Scada-Mapping/combined_technique_to_scada_similarity.csv")

    # Filter CSV to only scenario-relevant techniques by ID
    #filtered = match_df[match_df["TechniqueID"].isin(scenario_technique_ids)]

    # Match each SCADA_Description with a component in dependency_model
    #affected_components = set()
    #for _, row in filtered.iterrows():
    #    scada_desc = row["SCADA_Description"].strip()
    #    for comp in dependency_model.values():
    #        if comp["description"].strip() == scada_desc:
    #            affected_components.add(comp["name"])
    #            break  # stop once matched
    #print(affected_components)

    # Get mitigations per playbook
    mitigations = get_attack_technique_coverage_per_playbook(sparql_query_file)
    #print(mitigations)
    
    # Compute attack coverage per playbook
    #attack_coverage = {
    #    pb: (len(mitigations.get(pb, set())) ) / len(technique_labels)
    #    for pb in all_playbooks
    #}
    #print(attack_coverage)


    # Get asset coverage and playbook assets
    #asset_coverage = get_playbook_asset_coverage(affected_components)

    # Get defense step coverage
    (unique_step_number, step_counts, redundancy,
    completeness, defend_coverage) = get_defense_step_coverage(sparql_query_file, scenario_technique_ids)
    
    artifact_mappings, scenario_artifacts = get_artifact_coverage_per_playbook(sparql_query_file)

    artifact_coverage = {
        pb: len(artifact_mappings.get(pb, set())) / len(scenario_artifacts)
        for pb in all_playbooks if pb in artifact_mappings
    }
    
    # Debug prints
    #print(f"\n[DEBUG] Scenario '{scenario_name}' Digital Artifact Coverage:")
    #print(f"  - Total scenario artifacts: {len(scenario_artifacts)}")
    #print(f"  - Artifact coverage per playbook:")

    #artifact_coverage = {}
    #for pb in all_playbooks:
        #num_matched = len(artifact_mappings.get(pb, set()))
        #coverage_ratio = num_matched / len(scenario_artifacts) if scenario_artifacts else 0
        #artifact_coverage[pb] = coverage_ratio
        #print(f"    • {pb}: {num_matched}/{len(scenario_artifacts)} ({coverage_ratio:.2%})")


    #print("\n Defense Evaluation Summary:\n")
    #for pb in sorted(defend_coverage, key=defend_coverage.get, reverse=True):
        #print(f" Playbook {pb}:")
        #print(f"    Unique Defenses: {unique_step_number[pb]}")
        #print(f"    Total Defense Steps: {step_counts[pb]}")
        #print(f"    Redundant Steps: {redundancy[pb]}")
        #print(f"    Completeness Score: {completeness[pb]:.2%}")
        #print(f"    Adjusted Completeness (penalized): {defend_coverage[pb]:.2%}")

    # Define weights
    weights = {
        "defense": 0.5,
        "artifact": 0.5
    }


    # Compute weighted relevance score
    relevance_scores = {}
    for pb in all_playbooks:
        score = (
            weights["defense"] * defend_coverage.get(pb, 0) +
            weights["artifact"] * artifact_coverage.get(pb, 0)
        )
        relevance_scores[pb] = score
        
    SCORES_DIR.mkdir(parents=True, exist_ok=True)

    with open(SCORES_DIR / f"{scenario_name}_mcdm_scores.json", "w") as f:
        json.dump(relevance_scores, f)
        
    # Save defense coverage
    with open(SCORES_DIR / f"{scenario_name}_defense_coverage.json", "w") as f:
        json.dump(defend_coverage, f)

    # Save artifact coverage
    with open(SCORES_DIR / f"{scenario_name}_artifact_coverage.json", "w") as f:
        json.dump(artifact_coverage, f)
    
    

    # Show ranked playbooks
    ranked_playbooks = sorted(relevance_scores.items(), key=lambda x: x[1], reverse=True)

    if not ranked_playbooks:
        print(f"  No relevant playbooks found for scenario: {scenario_name}")
        continue

    # Top-ranked playbook by MCDM
    max_score = ranked_playbooks[0][1]
    top_mcdm_pbs = [pb for pb, score in ranked_playbooks if score == max_score]

    top_mcdm_pb = top_mcdm_pbs[0]
    # Raw scores
    defense_cov = defend_coverage.get(top_mcdm_pb, 0)
    artifact_cov = artifact_coverage.get(top_mcdm_pb, 0)

    # Contributions
    c_defense = weights["defense"] * defense_cov
    c_artifact = weights["artifact"] * artifact_cov

    final_score_percent = (c_defense + c_artifact) * 100

    # Compute Change in Operations (CiO)
    #cio_results = compute_cio(
    #    all_playbooks,
    #    best_relevant_playbooks,
    #    playbook_component_mapping,
    #    dependency_model,
    #    affected_components
    #)

    #if not cio_results:
    #    print(f"  No CiO results found for scenario: {scenario_name}")
    #    continue

    # Top-ranked playbook by operational impact (CiO)
    #max_cio_delta = max(val[2] for val in cio_results.values())
    #top_cio_pbs = [(pb, vals) for pb, vals in cio_results.items() if vals[2] == max_cio_delta]
    
    # Use the first for detailed score output
    #top_cio_pb, (cio_degraded, cio_restored, cio_delta) = top_cio_pbs[0]
    
    if final_score_percent == 0.0:
        print(f"  MCDM score is 0.0 for scenario '{scenario_name}'. Keeping explicit zero score.")

    # Normalize zero CiO delta
    #if cio_delta == 0.0:
    #    print(f"  CiO delta is 0.0 for scenario '{scenario_name}', CiO fields will be left blank.")
    #    top_cio_pb = ""
    #    cio_degraded = ""
    #    cio_restored = ""
    #    cio_delta = ""


    # Only include results with non-zero MCDM coverage
    
    all_results.append({
        "Scenario": scenario_name,
        "Top_MCDM_Playbook": ", ".join(top_mcdm_pbs),
        "MCDM_Score": f"{final_score_percent:.2f}%" if isinstance(final_score_percent, (float, int)) else "",
        "Artifact_Coverage": f"{artifact_cov*100:.2f}%" if isinstance(artifact_cov, (float, int)) else "",
        "Defense_Coverage": f"{defense_cov*100:.2f}%" if isinstance(defense_cov, (float, int)) else "",
    })


# Save results to CSV
df_results = pd.DataFrame(all_results)
# Compute average MCDM Score
avg_mcdm_score = df_results["MCDM_Score"].str.rstrip('%').astype(float).mean()

# Append average row
df_results.loc[len(df_results.index)] = {
    "Scenario": "Average",
    "Top_MCDM_Playbook": "",
    "Defense_Coverage": "",
    "Artifact_Coverage": "",
    "MCDM_Score": f"{avg_mcdm_score:.2f}%",
    "Verdict": ""
}

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
output_csv = OUTPUT_DIR / "scenario_playbook_evaluation.csv"
df_results.to_csv(output_csv, index=False)
print(f"\n All scenarios processed. Results saved to '{output_csv}'.")




end_time = time.time()
end_memory = process.memory_info().rss / (1024 * 1024)  # in MB
end_cpu_time = process.cpu_times().user
print(process.cpu_percent())

execution_time = end_time - start_time
memory_used = end_memory - start_memory
#cpu_time_used = end_cpu_time - start_cpu_time

print("\n=== Performance Metrics ===")
print(f"Total Execution Time: {execution_time:.2f} seconds")
print(f"RAM Usage: {memory_used:.2f} MB")
print(f"Total CPU: {process.cpu_percent():.2f}")
