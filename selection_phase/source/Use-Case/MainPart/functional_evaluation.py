import json
import os
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import matplotlib.pyplot as plt
from sparql_query_execution import get_attack_technique_coverage_per_playbook, get_technique_uris_for_scenario,get_technique_labels_from_uris
import psutil, time
from pathlib import Path

"""
Evaluate ATT&CK technique coverage of selected playbooks across multiple scenarios.

For each scenario, the script:
1. Loads the top-ranked MCDM playbooks and retrieves scenario-specific techniques.
2. Computes how many attack techniques are covered by the playbooks.
3. Calculates evaluation metrics:  recall of the top playbook.
4. Compares coverage with all available playbooks to find maximum possible recall and best-recall playbooks.
5. Saves detailed metrics to a CSV file and generates a visual table summarizing coverage and performance.

This allows assessing the effectiveness of playbook selection in mitigating scenario-specific attacks.
"""

# Folder with your SPARQL queries
sparql_folder = "Use-Case/SparqlQueryGeneration/SPARQL_QUERIES"
evaluation_metrics = []
OUTPUT_DIR = Path(os.getenv("SELECTION_OUTPUT_DIR", "out/selection"))

# Load MCDM results
df_results = pd.read_csv(OUTPUT_DIR / "scenario_playbook_evaluation.csv")

df_results["Scenario"] = df_results["Scenario"].str.replace('"', '').str.strip()
df_results = df_results[df_results["Scenario"].str.lower() != "average"]

#get all attack ids for the functional evaluation from mitre attack
ATTACK_ID_FILE = "Use-Case/MainPart/attack_ids/enterprise_attack_ids.txt"
with open(ATTACK_ID_FILE, encoding="utf-8") as f:
    ALL_ATTACK_IDS = {line.strip() for line in f if line.strip()}

for filename in os.listdir(sparql_folder):
    if not filename.endswith(".sparql"):
        continue

    scenario_name = filename.replace("df_SCENARIO_", "").replace(".sparql", "").strip()
    sparql_query_path = os.path.join(sparql_folder, filename)

    try:
        top_pb_str = df_results[(df_results["Scenario"]) == scenario_name]["Top_MCDM_Playbook"].values[0]
        if not top_pb_str:
            continue

        top_pb_ids = [pb.strip() for pb in top_pb_str.split(",") if pb.strip()]
        num_playbooks_used = len(top_pb_ids)
        
        technique_uris, _ = get_technique_uris_for_scenario(sparql_query_path)
        technique_labels = get_technique_labels_from_uris(technique_uris)
        true_techniques = set(technique_labels.keys())

        mitigations = get_attack_technique_coverage_per_playbook(sparql_query_path)

        covered_techniques = set()
        for pb in top_pb_ids:
            for uri in mitigations.get(pb, set()):
                tech_id = uri.split("#")[-1]
                covered_techniques.add(tech_id)

        # Expand universe to all techniques mentioned in any playbook
        all_playbook_techniques = ALL_ATTACK_IDS
        all_ids = sorted(true_techniques | covered_techniques | all_playbook_techniques)

        y_true = [1 if tid in true_techniques else 0 for tid in all_ids]
        y_pred = [1 if tid in covered_techniques else 0 for tid in all_ids]
        #print("→ Scenario:", scenario_name)
        #print("True Techniques:", true_techniques)
        #print("Covered Techniques:", covered_techniques)
        #print("False Positives:", covered_techniques - true_techniques)
        #print("False Negatives:", true_techniques - covered_techniques)

        #precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        #f1 = f1_score(y_true, y_pred, zero_division=0)
        #accuracy = accuracy_score(y_true, y_pred)


        # Find best possible recall from all available playbooks
        max_recall = 0
        best_recall_playbook = None

        for pb_id, uris in mitigations.items():
            covered_ids = {uri.split("#")[-1] for uri in uris}
            tp = len(covered_ids & true_techniques)
            fn = len(true_techniques - covered_ids)
            recall_pb = tp / (tp + fn) if (tp + fn) > 0 else 0
            if recall_pb > max_recall:
                max_recall = recall_pb
                best_recall_playbook = pb_id
                
        # Load MCDM relevance scores for the current scenario
        mcdm_scores_path = f"Use-Case/mcdm_scores_per_scenario/{scenario_name}_mcdm_scores.json"
        defense_cov_path = f"Use-Case/mcdm_scores_per_scenario/{scenario_name}_defense_coverage.json"
        artifact_cov_path = f"Use-Case/mcdm_scores_per_scenario/{scenario_name}_artifact_coverage.json"

        if os.path.exists(mcdm_scores_path):
            with open(mcdm_scores_path, "r") as f:
                relevance_scores = json.load(f)
            best_recall_mcdm_score = relevance_scores.get(best_recall_playbook, 0)
        else:
            best_recall_mcdm_score = 0

        if os.path.exists(defense_cov_path):
            with open(defense_cov_path, "r") as f:
                defense_coverage = json.load(f)
            best_recall_defense_cov = defense_coverage.get(best_recall_playbook, 0)
        else:
            best_recall_defense_cov = 0

        if os.path.exists(artifact_cov_path):
            with open(artifact_cov_path, "r") as f:
                artifact_coverage = json.load(f)
            best_recall_artifact_cov = artifact_coverage.get(best_recall_playbook, 0)
        else:
            best_recall_artifact_cov = 0
            
        is_optimal = abs(recall - max_recall) < 1e-6

        evaluation_metrics.append({
            "Scenario": scenario_name,
            "#Total Techniques": len(true_techniques),
            "#Covered Techniques": len(covered_techniques),
            "Recall": recall,
            "MCDM Chosen Playbook": top_pb_str,
            "Top is Optimal": is_optimal,
            "Max Recall (All Playbooks)": max_recall,
            "Best Recall Playbook": best_recall_playbook,
            "Best Recall MCDM Score": f"{best_recall_mcdm_score * 100:.2f}%",
            "Best Recall Defense Coverage": f"{best_recall_defense_cov * 100:.2f}%",
            "Best Recall Artifact Coverage": f"{best_recall_artifact_cov * 100:.2f}%"
        })

    except Exception as e:
        print(f"Skipping scenario {scenario_name}: {e}")
        continue

# Save results
eval_df = pd.DataFrame(evaluation_metrics)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
metrics_csv = OUTPUT_DIR / "ontology_coverage_metrics.csv"
eval_df.to_csv(metrics_csv, index=False)
print(f" Evaluation metrics saved to '{metrics_csv}'")

# === Display table ===
fig, ax = plt.subplots(figsize=(12, len(eval_df)*0.6 + 1))
ax.axis("off")

font_size = max(8, 10 - len(eval_df) // 2)

# Display metric values with component ratios
table_display = []
for _, row in eval_df.iterrows():
    table_display.append([
        row["Scenario"],
        row["MCDM Chosen Playbook"],
        row["#Total Techniques"],
        row["#Covered Techniques"],
        f'{row["Recall"]:.2f}',
        f'{row["Max Recall (All Playbooks)"]:.2f}',
        "✓" if row["Top is Optimal"] else "✗"
])

headers = [
    "Scenario",
    "#Playbook ID",
    "#Total Techniques",
    "#Covered Techniques",
    "Recall",
    "Max Recall (All Playbooks)",
    "Top is Optimal"
]

table = ax.table(
    cellText=table_display,
    colLabels=headers,
    loc='center',
    cellLoc='center'
)
table.auto_set_font_size(False)
table.set_fontsize(font_size)
table.scale(1, 1.5)

plt.tight_layout()
plt.savefig(OUTPUT_DIR / "attack_coverage_metrics_table_with_ratios.png")
