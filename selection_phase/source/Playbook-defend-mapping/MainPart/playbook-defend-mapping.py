import pandas as pd
import torch
from sentence_transformers import SentenceTransformer, util
from pathlib import Path
import os

""" Creates a mapping between playbooks and D3FEND mechanisms using SBERT.
Calculates confidence scores of mappings and saves results in CSV format.
"""

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MIN_CONFIDENCE = float(os.getenv("MIN_D3FEND_MAPPING_CONFIDENCE", "0.35"))

# Load data
playbooks_df = pd.read_csv(PROJECT_ROOT / "Playbook-defend-mapping" / "Preprocessing" / "filtered_playbooks.csv")
d3fend_df = pd.read_csv(PROJECT_ROOT / "Playbook-defend-mapping" / "Preprocessing" / "filtered_defensive_techniques.csv")

# Load SBERT model
model = SentenceTransformer("all-MiniLM-L6-v2")

# Pre-encode D3FEND columns
d3fend_technique_names = d3fend_df["Technique Name"].fillna("").tolist()
d3fend_technique_descs = d3fend_df["Description_technique"].fillna("").tolist()
d3fend_subtechnique_names = d3fend_df["Sub-Technique"].fillna("").tolist()
d3fend_subtechnique_descs = d3fend_df["Description_subtechnique"].fillna("").tolist()
d3fend_actions = d3fend_df["Actions"].fillna("").tolist()
d3fend_artifacts = d3fend_df["Artifacts"].fillna("").tolist()

# Encode each field
technique_name_embeddings = model.encode(d3fend_technique_names, convert_to_tensor=True)
technique_desc_embeddings = model.encode(d3fend_technique_descs, convert_to_tensor=True)
subtechnique_name_embeddings = model.encode(d3fend_subtechnique_names, convert_to_tensor=True)
subtechnique_desc_embeddings = model.encode(d3fend_subtechnique_descs, convert_to_tensor=True)
action_embeddings = model.encode(d3fend_actions, convert_to_tensor=True)
artifact_embeddings = model.encode(d3fend_artifacts, convert_to_tensor=True)

# Match function using SBERT
def find_best_match(playbook_name, playbook_description, step_name, step_description, playbook_action, playbook_artifact):
    # Sanitize
    playbook_name = str(playbook_name or "")
    playbook_description = str(playbook_description or "")
    step_name = str(step_name or "")
    step_description = str(step_description or "")
    playbook_action = str(playbook_action or "")
    playbook_artifact = str(playbook_artifact or "")

    # Encode playbook inputs
    pb_name_emb = model.encode(playbook_name, convert_to_tensor=True)
    pb_desc_emb = model.encode(playbook_description, convert_to_tensor=True)
    step_name_emb = model.encode(step_name, convert_to_tensor=True)
    step_desc_emb = model.encode(step_description, convert_to_tensor=True)
    action_emb = model.encode(playbook_action, convert_to_tensor=True)
    artifact_emb = model.encode(playbook_artifact, convert_to_tensor=True)

    # Compute similarities
    score_pb_name = util.cos_sim(pb_name_emb, technique_name_embeddings)[0]
    score_pb_desc = util.cos_sim(pb_desc_emb, technique_desc_embeddings)[0]
    score_step_name = util.cos_sim(step_name_emb, subtechnique_name_embeddings)[0]
    score_step_desc = util.cos_sim(step_desc_emb, subtechnique_desc_embeddings)[0]
    score_action = util.cos_sim(action_emb, action_embeddings)[0]
    score_artifact = util.cos_sim(artifact_emb, artifact_embeddings)[0]

    # Weighted sum
    total_scores = (
        0.1 * score_pb_name +
        0.2 * score_pb_desc +
        0.1 * score_step_name +
        0.2 * score_step_desc +
        0.2 * score_action +
        0.2 * score_artifact
    )

    best_idx = int(torch.argmax(total_scores))
    best_score = float(total_scores[best_idx])
    best_match = d3fend_df.iloc[best_idx]["Sub-Technique"]

    if best_score < MIN_CONFIDENCE:
        return "No Match", best_score

    return best_match, best_score

# Run mapping
confidence_scores = []
mappings = []

for _, row in playbooks_df.iterrows():
    best_match, confidence = find_best_match(
        row["playbook_name"],
        row["playbook_description"],
        row["step_names"],
        row["step_description"],
        row["action"],
        row["artifact"]
    )

    confidence_scores.append(confidence)
    mappings.append({
        "Playbook Name": row["playbook_name"],
        "Playbook ID": row["playbook_id"],
        "Playbook Description": row["playbook_description"],
        "Step Name": row["step_names"],
        "Step ID": row["step_id"],
        "Step Description": row["step_description"],
        "Playbook Action": row["action"],
        "Playbook Artifact": row["artifact"],
        "Best Matched D3FEND Technique": best_match if best_match else "No Match",
        "Confidence Score": round(confidence, 4)
    })

# Print score summary
print(f"\n Confidence Score Analysis:")
if confidence_scores:
    print(f" Lowest Confidence Score: {min(confidence_scores):.4f}")
    print(f" Highest Confidence Score: {max(confidence_scores):.4f}")
    print(f" Average Confidence Score: {sum(confidence_scores)/len(confidence_scores):.4f}")
    print(f" Mapping threshold: {MIN_CONFIDENCE:.4f}")
else:
    print(" No playbook rows available for mapping.")

# Save output
mapping_df = pd.DataFrame(mappings)
mapping_df.to_csv(PROJECT_ROOT / "Playbook-defend-mapping" / "MainPart" / "playbook_defend_mapping.csv", index=False)

print(" SBERT-based mapping completed and saved.")
