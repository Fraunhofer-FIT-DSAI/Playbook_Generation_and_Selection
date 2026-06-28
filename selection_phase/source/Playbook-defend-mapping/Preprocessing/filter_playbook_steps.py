import pandas as pd
""" Extracts relevant entities from playbooks for the mapping. """
# Load the CSV file
csv_file = "Playbook//steps-coded.csv"  
df = pd.read_csv(csv_file, delimiter=";")  

# Select only the required columns
filtered_df = df[["playbook_name", "playbook_id", "playbook_description", "step_names", "step_id", "step_description", "action", "artifact"]]

# Save extracted data to a new CSV file
filtered_csv = "Playbook-defend-mapping//Preprocessing//filtered_playbooks.csv"
filtered_df.to_csv(filtered_csv, index=False)

print(f"Extracted data saved to {filtered_csv}")
