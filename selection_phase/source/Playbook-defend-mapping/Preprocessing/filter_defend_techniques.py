from owlready2 import *
import pandas as pd
""" Extracts relevant entities from defend owl for the mapping. """

# Load the ontology
ontology_path = "Playbook-defend-mapping//Preprocessing//d3fend.owl"   
onto = get_ontology(ontology_path).load()

# Identify key ontology classes
defensive_technique_class = None

for cls in onto.classes():
    if "DefensiveTechnique" in cls.name:  # Check for variations in naming
        defensive_technique_class = cls

# analyze a single technique and extract its relationships
def analyze_technique(technique):
    actions = set()
    artifacts = set()

    for prop in technique.is_a: 
        if isinstance(prop, Restriction): 
            action_name = prop.property.name  # Extract action
            if hasattr(prop.value, "name"):  # Ensure the value: has a name
                artifact_name = prop.value.name  # Extract artifact 
                actions.add(action_name)
                artifacts.add(artifact_name)

    return list(actions), list(artifacts)

# Apply this function to all subclasses of defensive techniques
def extract_defensive_techniques():
    if defensive_technique_class:
        techniques = []

        for technique in defensive_technique_class.subclasses():  # Loop through main techniques
            for sub_tech in technique.subclasses():  # Loop through sub-techniques
                actions, artifacts = analyze_technique(sub_tech)
                description_subtechnique = sub_tech.definition[0] if hasattr(sub_tech, "definition") and sub_tech.definition else "No description available"
                description_techique = technique.definition[0] if hasattr(technique, "definition") and technique.definition else "No description available"

                techniques.append({
                    "Technique Name": technique.name,
                    "Sub-Technique": sub_tech.name,
                    "Description_technique": description_techique,
                    "Description_subtechnique": description_subtechnique,
                    "Actions": ", ".join(actions) if actions else "None",
                    "Artifacts": ", ".join(artifacts) if artifacts else "None"
                })

        return pd.DataFrame(techniques)
    else:
        print("Defensive Technique class not found in ontology.")
        return pd.DataFrame()

# Run extraction
techniques_df = extract_defensive_techniques()

# Save extracted techniques to a CSV file
csv_filename = "Playbook-defend-mapping//Preprocessing//filtered_defensive_techniques.csv"
if not techniques_df.empty:
    techniques_df.to_csv(csv_filename, index=False)  
    print(f"\n Data saved to {csv_filename}")
else:
    print("No data extracted.")

