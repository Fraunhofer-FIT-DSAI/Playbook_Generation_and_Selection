import pandas as pd
from def3nd.def3nd import get_root_defensive_technique
import re
from cvss import CVSS3
import copy



# Load the CSV into a DataFrame


def add_spaces_to_camel_case(name: str) -> str:
    return re.sub(r'(?<!^)(?=[A-Z])', ' ', name)



#class Countermeasures:
#    def __init__(self):
full_mapping_path = "defense_techniques/d3fend-full-mappings.csv"  # Update with your actual file path
df = pd.read_csv(full_mapping_path)
uri = 'http://d3fend.mitre.org/ontologies/d3fend.owl#'
techniques_root_mapping_path = "defense_techniques/technique_root_mapping.csv"
techniques_root_mapping_df = pd.read_csv(techniques_root_mapping_path)
techniques_root_mapping = techniques_root_mapping_df.set_index('Technique')['RootTechnique'].to_dict()

tactic_df = pd.read_csv("Response_generation/defend_cvss.csv")




required_columns = [
    'query_def_tech_label', 
    'top_def_tech_label', 
    'def_tech_label', 
    'def_tactic_label', 
    'def_tactic_rel_label', 
    'def_artifact_rel_label', 
    'def_artifact_label', 
    'off_artifact_label', 
    'off_artifact_rel_label', 
    'off_tech_label', 
    'off_tech_id'
    ]

df = df[required_columns]

df['off_tech_id'] = df['off_tech_id'].astype(str).str.strip()
df['off_tech_parent_id'] = df['off_tech_id'].str.split('.').str[0]

attack_IDs = list(df['off_tech_id'].unique())

#def create_artifact_mapping():


# Function to filter by attack_id and group by off_artifact_label
def filter_and_group_by_attack_id(attack_id):
    attack_id = str(attack_id).strip()
    filtered_df = df[df['off_tech_id'] == attack_id]
    if filtered_df.empty and "." in attack_id:
        filtered_df = df[df['off_tech_parent_id'] == attack_id.split(".")[0]]


    countermeasures_df = filtered_df[['off_tech_id', 'def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']]

    mapped_rows = []
    strategies = []

    for index, row in countermeasures_df.iterrows():
        #artifact = row['off_artifact_label']
        technique = row['def_tech_label']
        technique = technique.replace(" ", "")
        #print(technique)
        strategy = techniques_root_mapping.get(technique)
        if not strategy:
            continue
        #strategy = add_spaces_to_camel_case(strategy)
        #print(strategy)
        mapped_rows.append(row)
        strategies.append(strategy)
                
                
    if not mapped_rows:
        return countermeasures_df.iloc[0:0].copy()

    countermeasures_df = pd.DataFrame(mapped_rows).copy()
    countermeasures_df['strategies'] = strategies

    return countermeasures_df


def escalate(val):
        """Escalate N → L → H"""
        cvss_scale = ['N', 'L', 'H']
        try:
            idx = cvss_scale.index(val)
            return cvss_scale[min(idx + 1, 2)]
        except ValueError:
            return val

def deescalate(val):
    """Deescalate H → L → N"""
    cvss_scale = ['N', 'L', 'H']
    try:
        idx = cvss_scale.index(val)
        return cvss_scale[max(idx - 1, 0)]
    except ValueError:
        return val

def adjust_cvss(cvss_vector: str, tactic_data: pd.DataFrame) -> tuple[str, float]:
    cvss_scale = ['N', 'L', 'H']
    try:
        vector_dict = {item.split(":")[0]: item.split(":")[1] for item in cvss_vector.split("/")[1:]}
    except Exception as e:
        #print(f"Failed to parse CVSS vector: {e}")
        return cvss_vector, None

    for _, row in tactic_data.iterrows():
        for metric in ['AC', 'PR', 'UI', 'C', 'I', 'A']:  
            adjustment = row.get(metric)
            if pd.isna(adjustment) or adjustment == 'NE':
                continue

            if metric == 'UI':
                if adjustment == 'High':
                    vector_dict[metric] = 'R'
                elif adjustment == 'Low':
                    vector_dict[metric] = 'N'
                continue

            current_val = vector_dict.get(metric)
            if current_val not in cvss_scale:
                continue

            if adjustment == 'High':
                vector_dict[metric] = escalate(current_val)
            elif adjustment == 'Low':
                vector_dict[metric] = deescalate(current_val)

        # Reconstruct vector (preserve original ordering)
    new_vector = "CVSS:3.1/" + "/".join([f"{k}:{v}" for k, v in vector_dict.items()])

    try:
        new_score = CVSS3(new_vector).base_score
    except Exception as e:
        #print(f"Error computing score: {e}")
        new_score = None

    return new_vector, new_score


def extract_exploitability_and_impact(vector):
        metrics = dict(segment.split(':') for segment in vector.split('/')[1:])
        
        # Exploitability Metrics Weights
        AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        AC = {'L': 0.77, 'H': 0.44}
        PR_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        PR_C = {'N': 0.85, 'L': 0.68, 'H': 0.5}
        UI = {'N': 0.85, 'R': 0.62}
        
        # Impact Metrics Weights
        impact_weights = {'H': 0.56, 'L': 0.22, 'N': 0.0}
        
        scope = metrics['S']
        
        AV_val = AV[metrics['AV']]
        AC_val = AC[metrics['AC']]
        PR_val = PR_C[metrics['PR']] if scope == 'C' else PR_U[metrics['PR']]
        UI_val = UI[metrics['UI']]
        
        C = impact_weights[metrics['C']]
        I = impact_weights[metrics['I']]
        A = impact_weights[metrics['A']]
        
        exploitability = 8.22 * AV_val * AC_val * PR_val * UI_val
        impact = 1 - ((1 - C) * (1 - I) * (1 - A))
        impact *= 6.42 if scope == 'U' else 7.52
        return round(exploitability, 2), round(impact, 2)
    


def calculate_risk(incident):
    total_risk = 0.0
    cumulative_exploitability = 1.0
    cumulative_impact = 0.0

    for step in incident:
        exploitability = float(step.get('exploitability', 0.0)) / 10  # Normalize to probability
        impact = float(step.get('impact', 0.0))

        cumulative_exploitability *= exploitability
        cumulative_impact += impact

        risk_i = cumulative_exploitability * cumulative_impact
        total_risk += risk_i

    return total_risk


def create_countermeasure_table(incident, top_k=3):
    dfs = []

    hosts = []
    attack_ids = []
    cvss_vectors = []
    
    risk = calculate_risk(incident)

    for step in incident:
        hosts.append(step['host'])
        attack_id = step['mitre'].split()[-1]
        attack_ids.append(attack_id)
        cvss_vectors.append(step['cvss_vector'])


    for i, (host, attack_id, cvss_vector) in enumerate(zip(hosts, attack_ids, cvss_vectors)):
        df = filter_and_group_by_attack_id(attack_id)
        if df.empty:
            continue


        df['host'] = host
        df['risk'] = calculate_risk(incident)
        df['cvss_vector'] = cvss_vector
        df['risk_reduction'] = 0.0  # Initialize column


        for idx, row in df.iterrows():
            strategy = row['strategies']  # Assuming this column exists in `df`
            tactic_row = tactic_df[tactic_df['def_tactic'] == strategy]

            if tactic_row.empty:
                continue  # Skip if no tactic found

            new_vector, new_score = adjust_cvss(cvss_vector, tactic_row)

            if new_score is not None:
                modified_incident = copy.deepcopy(incident)
                
                exploitability, impact = extract_exploitability_and_impact(new_vector)
                modified_incident[i]['exploitability'] = exploitability
                modified_incident[i]['impact'] = impact

                new_risk = calculate_risk(modified_incident)
                risk_reduction = risk - new_risk

                df.at[idx, 'risk_reduction'] = risk_reduction

        if not df.empty:
            dfs.append(df)

    if not dfs:
        empty_columns = required_columns + ['strategies', 'host', 'risk', 'cvss_vector', 'risk_reduction']
        return pd.DataFrame(columns=empty_columns), risk, risk

    combined_df = pd.concat(dfs, ignore_index=True)

    #print(combined_df)

    tactic_labels = ['Detect', 'Isolate', 'Evict', 'Restore']

    detection_df = combined_df[combined_df['def_tactic_label'] == 'Detect'] \
        .sort_values(by='risk_reduction', ascending=False).head(top_k)

    containment_df = combined_df[combined_df['def_tactic_label'] == 'Isolate'] \
        .sort_values(by='risk_reduction', ascending=False).head(top_k)

    eradication_df = combined_df[combined_df['def_tactic_label'] == 'Evict'] \
        .sort_values(by='risk_reduction', ascending=False).head(top_k)

    recovery_df = combined_df[combined_df['def_tactic_label'] == 'Restore'] \
        .sort_values(by='risk_reduction', ascending=False).head(top_k)

    
    # Collect all DataFrames into one list
    selected_countermeasures_dfs = [detection_df, containment_df, eradication_df, recovery_df]

    selected_countermeasures = pd.concat(selected_countermeasures_dfs, ignore_index=True)
    dedup_columns = [
        'off_tech_id',
        'def_tech_label',
        'def_tactic_label',
        'def_artifact_label',
        'host',
    ]
    selected_countermeasures = selected_countermeasures \
        .sort_values(by='risk_reduction', ascending=False) \
        .drop_duplicates(subset=dedup_columns, keep='first')

    # Extract unique (strategy, cvss_vector) pairs as a list of tuples
    unique_strategies = list(
        selected_countermeasures[['strategies', 'cvss_vector', 'host']].drop_duplicates().itertuples(index=False, name=None)
    )

    incident_copy = copy.deepcopy(incident)

    # Loop through each unique strategy entry
    for strategy, original_vector, host in unique_strategies:
        # Find the tactic row corresponding to the strategy
        tactic_row = tactic_df[tactic_df['def_tactic'] == strategy]
        if tactic_row.empty:
            continue  # Skip if no tactic match

        # Adjust the CVSS vector using the tactic
        new_vector, new_score = adjust_cvss(original_vector, tactic_row)

        # Extract exploitability and impact if new_score is available
        if new_score is not None:
            exploitability, impact = extract_exploitability_and_impact(new_vector)

            # Update the matching host in the incident copy
            for step in incident_copy:
                if step['host'] == host:
                    step['cvss_vector'] = new_vector
                    step['cvss_score'] = new_score
                    step['exploitability'] = exploitability
                    step['impact'] = impact
                    break  # Assume one match per host

    # Recalculate risk after updates
    updated_risk = calculate_risk(incident_copy)

    return selected_countermeasures, risk, updated_risk


incident = [
    {
        "host": "web-server",
        "mitre": "T1190",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploitability": 3.9,  # Example value from extract_exploitability_and_impact
        "impact": 5.9           # Example value from extract_exploitability_and_impact
    },
    {
        "host": "db-server",
        "mitre": "T1040",
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "exploitability": 1.8,
        "impact": 4.1
    },
    {
        "host": "app-server",
        "mitre": "T1059",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N",
        "exploitability": 2.5,
        "impact": 3.7
    }
]




def filter_attack_IDs(attack_IDs):
    attacks = []
    for attack_id in attack_IDs:
        filter_by_attack_ID = df[df['off_tech_id'] == attack_id]


        countermeasures_df = filter_by_attack_ID[['def_tech_label', 'off_artifact_label', 'def_tactic_label']]

        
        isContain = False
        isEradicate = False
        isRecovery = False
        isDetect = False
        for index, row in countermeasures_df.iterrows():

            stage = row['def_tactic_label']
            if stage == 'Detect':
                isDetect = True
            elif stage == 'Isolate':
                isContain = True          
            elif stage == 'Evict':
                isEradicate = True
            elif stage == 'Restore':
                isRecovery = True

        if isDetect and isContain and isEradicate and isRecovery:
            attacks.append(attack_id)
    
    #print(attacks)


def get_defenses(attack_id):
    attack_id_df = df[df['off_tech_id'] == attack_id]
    defense_df = attack_id_df[['def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']].drop_duplicates()

def get_containments(attack_id):
    attack_id_df = df[df['off_tech_id'] == attack_id]
    defense_df = attack_id_df[['def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']].drop_duplicates()
    contain_df = defense_df[defense_df['def_tactic_label'] == 'Isolate'] 
    return contain_df

def get_detections(attack_id):
    attack_id_df = df[df['off_tech_id'] == attack_id]
    defense_df = attack_id_df[['def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']].drop_duplicates()
    detection_df = defense_df[defense_df['def_tactic_label'] == 'Detect'] 
    return detection_df


def get_detections_by_artifact(attack_id, artifact):
    attack_artifact_df = df[(df['off_tech_id'] == attack_id) & (df['off_artifact_label'] == artifact)]
    defense_df = attack_artifact_df[['def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']].drop_duplicates()
    detection_df = defense_df[defense_df['def_tactic_label'] == 'Detect'] 
    detection_df = detection_df.drop_duplicates()
    return detection_df

def get_containments_by_artifact(attack_id, artifact):
    attack_artifact_df = df[(df['off_tech_id'] == attack_id) & (df['off_artifact_label'] == artifact)]
    defense_df = attack_artifact_df[['def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']]
    containment_df = defense_df[defense_df['def_tactic_label'] == 'Isolate'] 
    containment_df = containment_df.drop_duplicates()
    return containment_df


def get_eradications(attack_id):
    attack_id_df = df[df['off_tech_id'] == attack_id]
    defense_df = attack_id_df[['def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']].drop_duplicates()
    evict_df = defense_df[defense_df['def_tactic_label'] == 'Evict'] 
    return evict_df

def get_eradications_by_artifact(attack_id, artifact):
    attack_artifact_df = df[(df['off_tech_id'] == attack_id) & (df['off_artifact_label'] == artifact)]
    defense_df = attack_artifact_df[['def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']]
    eradicatoin_df = defense_df[defense_df['def_tactic_label'] == 'Evict'] 
    eradicatoin_df = eradicatoin_df.drop_duplicates()
    return eradicatoin_df

def get_tactics_by_attack_tech(attack_id):
    """
    Returns a list of unique 'def_tactic_label' values
    where 'off_tech_id' matches the given attack_id.
    """
    filtered = df[df['off_tech_id'] == attack_id]
    return filtered['def_tactic_label'].dropna().unique().tolist()
