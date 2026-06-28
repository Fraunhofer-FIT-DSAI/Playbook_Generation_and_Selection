from math import prod
import copy
from collections import defaultdict
import pandas as pd
from sparql_query_execution import get_technique_labels_from_uris


""" Calculates the the operatinal impact of the playbooks on the Scada dependency model  """


def assign_cvss_to_scada_components(enriched_mapping, scada_mapping_csv, temp_model):
    scada_df = pd.read_csv(scada_mapping_csv)
    enriched_df = pd.DataFrame(enriched_mapping)

    # Merge on matching Asset and MITRE Asset (device)
    merged = pd.merge(
        scada_df,
        enriched_df,
        left_on="MITRE Asset",
        right_on="Asset",
        how="left"
    )

    # Assign CVSS to corresponding components in the model
    for _, row in merged.iterrows():
        comp_name = row["SCADA Component Name"].strip()
        cvss_score = row["CVSS_Score"]
        if pd.notnull(cvss_score):
            comp_key = next((k for k, v in temp_model.items() if v.get("name", "").strip() == comp_name), None)
            if comp_key:
                temp_model[comp_key]["probability"] = cvss_score/10
                print(f" - {comp_name} (key: {comp_key}): CVSS {cvss_score} → probability {cvss_score / 10:.2f}")


    return temp_model


def is_or_grouping(description: str) -> bool:
    """
    Returns True if the description implies an OR-dependency, i.e.,
    a categorical grouping of interchangeable components.
    Detected via the presence of 'are' in the sentence.
    """
    if not description:
        return False

    return " are " in description.lower()




def find_top_components(dependency_model):
    """Find top-most component using safe key-based dependency resolution.
    Idea: find all dependent components and top components, extract dependent components and
    return the top-most component"""

    # Create reverse lookup: name → list of keys
    name_to_keys = defaultdict(list)
    for key, val in dependency_model.items():
        name = val.get("name", "").strip()
        name_to_keys[name].append(key)

    # Gather all component keys
    all_components = set(dependency_model.keys())

    # Resolve dependencies to actual keys
    all_dependencies = set()
    for comp_key, val in dependency_model.items():
        dep_names = val.get("dependencies", [])

        for dep_name in dep_names:
            matched_keys = name_to_keys.get(dep_name, [])
            if matched_keys:
                all_dependencies.update(matched_keys)
            else:
                print(f" Could not resolve dependency '{dep_name}' for component '{comp_key}'")

    # Find root components (i.e., not dependent on any others)
    root_components = sorted(all_components - all_dependencies)

    # Return the first root component if any
    return root_components[0] if root_components else None





def calculate_CiO(affected_components, dependency_model,top_component, attack_components):
    """Calculates Change in Operations (CiO) using probability-based degradation for a playbook from compute_cio function.
    Reduce the value for the affected components to 0.5 and calculate the operatinal value for the top component
    recursively"""
    
    visited_components = set()

    
    # Ensure dependencies are stored as lists during copying
    temp_model = copy.deepcopy(dependency_model)
        
    # Initial component probabilities set to 1.0       
    for component in temp_model:
        temp_model[component]["probability"] = 1.0


    tech_to_asset_df = pd.read_csv("Techniqe-Scada-Mapping/combined_technique_to_scada_similarity.csv")
    tech_to_cvss_df = pd.read_csv("Attack-CVE-Mapping/merged_attack_capec_mapping_with_cvss.csv")  # Adjust path as needed
    
        # Merge technique → asset and technique → CVSS score
    tech_asset_cvss = pd.merge(
        tech_to_asset_df,
        tech_to_cvss_df,
        left_on="TechniqueName",  # from best match CSV
        right_on="technique",     # from CVSS CSV
        how="inner"
    )
    
    # Remove duplicate assignments
    tech_asset_cvss = tech_asset_cvss.drop_duplicates(subset=["SCADA_Description", "cvss_score"])
    #print(attack_components)


    # Step 1: Build name → description lookup from dependency model
    name_to_desc = {
        v["name"].strip(): v["description"].strip()
        for v in temp_model.values()
    }

    # Step 2: Iterate over affected components by name
    for comp_name in attack_components:
        description = name_to_desc.get(comp_name)
        if not description:
            continue  # no matching description for this component

        # Step 3: Find corresponding CVSS score in the CSV
        matching_rows = tech_asset_cvss[tech_asset_cvss["SCADA_Description"].str.strip() == description]

        for _, row in matching_rows.iterrows():
            cvss_score = row["cvss_score"]
            if pd.notnull(cvss_score):
                # Find component key in temp_model by name
                comp_key = next((k for k, v in temp_model.items()
                                if v.get("name", "").strip() == comp_name), None)
                if comp_key:
                    temp_model[comp_key]["probability"] = float(cvss_score) / 10
                    #print(f" [CVSS Mapped] {comp_name} → {description} → {cvss_score} → {float(cvss_score)/10:.2f}")









    # Recursively update probabilities for parent components
    def update_probability(component):
        """Recursively compute probability for a component based on AND/OR dependencies."""
        visited_components.add(component)

        
        if component not in temp_model:
            print(f" Component key '{component}' not found!")
            return 1.0  # Default if component is missing

        #print(f"\n DEBUG: Processing Component '{component}'")
       
        # filter out empty dependencies
        dependencies = [dep for dep in temp_model[component]["dependencies"] if dep]
        
        #print(f"   DEBUG: Extracted Dependencies for '{component}': {dependencies}")
    
        if not dependencies:
            #print(f"    No dependencies found. Returning own probability: {temp_model[component]['probability']}")
            temp_model[component]["computed_probability"] = temp_model[component]["probability"]
            return temp_model[component]["probability"]
    
        dep_type = temp_model[component]["type"]
        dep_probabilities = []
        for dep_name in dependencies:
            # Try to find a matching component key where the name matches
            matching_key = next((k for k, v in temp_model.items() if v["name"] == dep_name), None)
            
            if not matching_key:
                print(f"   Missing dependency key: {dep_name}")
                dep_probabilities.append(1.0)  # Default fallback if not found
            else:
                if matching_key == component:
                    #print(f"   Skipped self-reference to '{component}'")
                    continue  # skip self-dependency
                #print(f"   Resolved '{dep_name}' → '{matching_key}'")
                dep_probabilities.append(update_probability(matching_key))

       
        base_probability = temp_model[component]["probability"]
        
        #print(f"    Computed Probabilities for '{component}' Dependencies: {dep_probabilities}")
        #print(f"    Dependency Type: {dep_type}")
        #print(f"    Current Probability Before Update: {temp_model[component]['probability']}")

        # Apply AND/OR logic, update the probability based on the dependencies	
        base_probability = temp_model[component]["probability"]
        if dep_type == "AND":
            result = base_probability * prod(dep_probabilities)
        elif dep_type == "OR":
            result = base_probability * (1 - prod(1 - p for p in dep_probabilities))
        else:
            result = base_probability  # Default case
            

        
        temp_model[component]["computed_probability"] = result
        #print(f"   Type: {dep_type}, Base: {base_probability:.3f}, Deps: {dep_probabilities} → Result: {result:.5f}")
        return result

    #print("\n DEBUG: Calculating degraded top probability")
    #print(f" Top Component Key: {top_component}")
    #print(f" Top Component Name: {temp_model[top_component]['name']}")
    #print(f" Current Probability: {temp_model[top_component]['probability']}")
    degraded_top_probability = update_probability(top_component)
    #print(f" Degraded Top Probability = {degraded_top_probability:.30f}")


    
    # Recover affected components using playbook
    for component in affected_components:
        mapped_key = next((k for k, v in temp_model.items() if v.get("name") == component), None)
        if mapped_key:
            temp_model[mapped_key]["probability"] = 1  # restore by playbook
            #print(f" Restored '{component}' to 1.0 by playbook")
            #print(f" Affected: {affected_components}")
            
    # Compute final probability for the top component
    restored_top_probability = update_probability(top_component)
    #print(f" Restored Top Probability = {restored_top_probability:.30f}")
    #print("\n Summary of Components Affecting Top Component:")
    #print(f"Total: {len(visited_components)} components")
    #print(f"Affected by Playbook: {[comp for comp in affected_components if any(temp_model[k]['name'] == comp for k in visited_components)]}")
    #print(f"Unrelated Affected Components: {[comp for comp in affected_components if all(temp_model[k]['name'] != comp for k in visited_components)]}")

    return degraded_top_probability, restored_top_probability

def compute_cio(all_playbooks, best_relevant_playbooks, playbook_component_mapping, dependency_model, attack_components):
    """Extracts affected components for the playbooks and calculates their operatinal impact
    Higher the CIO, better the playbook.
    """
    playbook_probabilities = {}
    top_component = find_top_components(dependency_model)
    #print(f"\n DEBUG: Identified Top Component: {top_component}")

    for playbook in sorted(all_playbooks):
        # Retrieve affected components
        #print(f"BEGIN FOR THE PLAYBOOK {playbook}")
        affected_components = sorted(playbook_component_mapping.get(playbook, []))
        
        #print(f"\n DEBUG: Extracted Affected Components for Playbook '{playbook}': {affected_components}")

        # Compute CIO
        degraded_prob, restored_prob = calculate_CiO(affected_components, dependency_model, top_component, attack_components)
        final_probability = restored_prob - degraded_prob
        playbook_probabilities[playbook] = (degraded_prob, restored_prob, final_probability)
        #print(f"END FOR THE PLAYBOOK {playbook}")
        
    # Sort playbooks from highest value to the lowest    
    sorted_playbooks = sorted(playbook_probabilities.items(), key=lambda x: x[1], reverse=True)

    # Debug: Print Playbook Probabilities Per Scenario
    print("\n Playbook Probabilities for Scenario:")
    for pb, (degraded_prob, restored_prob, final_probability) in sorted(playbook_probabilities.items(), key=lambda x: x[1][2], reverse=True):
        print(f"    Playbook {pb}: Degraded = {degraded_prob:.5f}, Restored = {restored_prob:.5f}, ∆CiO = {final_probability:.5f}")
        
    best_final_probability = sorted(playbook_probabilities.items(), key=lambda x: x[1][2], reverse=True)[0][1][2]
    best_playbooks = [pb for pb, prob in sorted_playbooks if prob == best_final_probability]
    
    #map the chosen playbook(s) by the ontology to its operational impact value
    most_frequent_probabilities = {pb: playbook_probabilities.get(pb, "N/A") for pb in best_relevant_playbooks}
    print(best_relevant_playbooks)

    print("\n Playbook(s) with the most relevant steps:")
    for pb, prob in most_frequent_probabilities.items():
        print(f"   - Playbook {pb}: Probability = {prob:.30f}" if isinstance(prob, float) else f"   - Playbook {pb}: Probability = N/A")

    print(f"\n Best Operational Playbook(s) = {best_final_probability:.30f}): {', '.join(best_playbooks)}")
    
    if any(pb in best_playbooks for pb in best_relevant_playbooks):
        print("\n Playbook(s) with the most relevant steps is also the best operationally! ")
    else:
        print("\n Playbook(s) with the most relevant steps is NOT the best operationally.")



    return playbook_probabilities  # instead of None

        
        
 
