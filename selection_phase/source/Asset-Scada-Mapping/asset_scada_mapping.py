import json
import pandas as pd
from rapidfuzz import fuzz

"""
Maps MITRE ICS ATT&CK assets (name & description) to SCADA dependency model components.
Allows one asset to match multiple SCADA components based on fuzzy similarity.
"""

# === Load MITRE ICS ATT&CK JSON ===
with open("Technique-Asset-Mapping/ics-attack.json", "r", encoding="utf-8") as file:
    mitre_data = json.load(file)

# Extract x-mitre-asset entries
mitre_assets = [
    {
        "name": obj.get("name", ""),
        "description": obj.get("description", "")
    }
    for obj in mitre_data["objects"]
    if obj.get("type") == "x-mitre-asset"
]

# === Load SCADA Dependency Model ===
scada_df = pd.read_csv("Use-Case/MainPart/dependency_model.csv")  # Must contain: Component ID, Component Name, Component Description

# === Matching Logic ===
matches = []

for asset in mitre_assets:
    for _, row in scada_df.iterrows():
        comp_name = str(row["Component Name"])
        comp_desc = str(row["Component Description"])

        name_score = fuzz.partial_ratio(asset["name"].lower(), comp_name.lower())
        desc_score = fuzz.partial_ratio(asset["description"].lower(), comp_desc.lower())

        score = max(name_score, desc_score)

        if score >= 70:  # You can tweak threshold
            matches.append({
                "MITRE Asset": asset["name"].replace("(", "").replace(")", "").replace(" ", "_"),
                "SCADA Component Name": comp_name,
                "Component ID": row["Component ID"],
                "Confidence Score": score
            })

# === Save Output ===
output_file = "Asset-Scada-Mapping/asset_to_scada_mapping.csv"
pd.DataFrame(matches).to_csv(output_file, index=False)

print(f" MITRE asset → SCADA component mapping saved to: {output_file}")
