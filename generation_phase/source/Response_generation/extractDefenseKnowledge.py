import math
from pathlib import Path

import pandas as pd
from cvss import CVSS3
import copy

SOURCE_ROOT = Path(__file__).resolve().parents[1]
full_mapping_path = SOURCE_ROOT / "defense_techniques" / "d3fend-full-mappings.csv"
df = pd.read_csv(full_mapping_path)
techniques_root_mapping_path = SOURCE_ROOT / "defense_techniques" / "technique_root_mapping.csv"
techniques_root_mapping_df = pd.read_csv(techniques_root_mapping_path)
techniques_root_mapping = techniques_root_mapping_df.set_index('Technique')['RootTechnique'].to_dict()

tactic_df = pd.read_csv(Path(__file__).resolve().parent / "defend_cvss.csv")
tactic_rows_by_strategy = {
    strategy: rows.to_dict(orient="records")
    for strategy, rows in tactic_df.groupby("def_tactic", dropna=False)
}




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

_countermeasure_cache = {}

def filter_and_group_by_attack_id(attack_id):
    attack_id = str(attack_id).strip()
    if attack_id in _countermeasure_cache:
        return _countermeasure_cache[attack_id].copy()

    filtered_df = df[df['off_tech_id'] == attack_id]
    if filtered_df.empty and "." in attack_id:
        parent = attack_id.split(".")[0]
        parent_exact = df[df['off_tech_id'] == parent]
        filtered_df = parent_exact if not parent_exact.empty else df[df['off_tech_parent_id'] == parent]


    countermeasures_df = filtered_df[['off_tech_id', 'def_tech_label', 'def_tactic_label', 'def_tactic_rel_label', 'def_artifact_rel_label', 'def_artifact_label']]

    mapped_rows = []
    strategies = []

    for _, row in countermeasures_df.iterrows():
        technique = row['def_tech_label']
        technique = technique.replace(" ", "")
        strategy = techniques_root_mapping.get(technique)
        if not strategy:
            continue
        mapped_rows.append(row)
        strategies.append(strategy)
                
                
    if not mapped_rows:
        return countermeasures_df.iloc[0:0].copy()

    countermeasures_df = pd.DataFrame(mapped_rows).copy()
    countermeasures_df['strategies'] = strategies
    countermeasures_df['matched_off_tech_id'] = countermeasures_df['off_tech_id']
    countermeasures_df['off_tech_id'] = attack_id

    _countermeasure_cache[attack_id] = countermeasures_df
    return countermeasures_df.copy()


def escalate(val):
    """Escalate N -> L -> H."""
    cvss_scale = ['N', 'L', 'H']
    try:
        idx = cvss_scale.index(val)
        return cvss_scale[min(idx + 1, 2)]
    except ValueError:
        return val

def deescalate(val):
    """Deescalate H -> L -> N."""
    cvss_scale = ['N', 'L', 'H']
    try:
        idx = cvss_scale.index(val)
        return cvss_scale[max(idx - 1, 0)]
    except ValueError:
        return val

def adjust_cvss(cvss_vector: str, tactic_data) -> tuple[str, float]:
    cvss_scale = ['N', 'L', 'H']
    try:
        vector_dict = {item.split(":")[0]: item.split(":")[1] for item in cvss_vector.split("/")[1:]}
    except Exception:
        return cvss_vector, None

    if isinstance(tactic_data, pd.DataFrame):
        tactic_rows = tactic_data.to_dict(orient="records")
    else:
        tactic_rows = tactic_data

    for row in tactic_rows:
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

    new_vector = "CVSS:3.1/" + "/".join([f"{k}:{v}" for k, v in vector_dict.items()])

    try:
        new_score = CVSS3(new_vector).base_score
    except Exception:
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
        iss = 1 - ((1 - C) * (1 - I) * (1 - A))
        if scope == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        impact = max(impact, 0.0)
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


def normalize_incident_for_risk(incident):
    """Use one CVSS computation for both baseline and adjusted path risk."""
    normalized = copy.deepcopy(incident)
    for step in normalized:
        try:
            exploitability, impact = extract_exploitability_and_impact(step.get('cvss_vector'))
        except Exception:
            continue
        step['exploitability'] = exploitability
        step['impact'] = impact
    return normalized


def create_countermeasure_table(incident, top_k=3):
    dfs = []
    adjustment_cache = {}
    risk_cache = {}

    hosts = []
    attack_ids = []
    cvss_vectors = []
    
    incident_for_risk = normalize_incident_for_risk(incident)
    risk = calculate_risk(incident_for_risk)
    empty_columns = required_columns + [
        'strategies', 'matched_off_tech_id', 'host', 'step_index',
        'risk', 'cvss_vector', 'risk_reduction',
    ]
    if top_k <= 0:
        return pd.DataFrame(columns=empty_columns), risk, risk

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
        df['step_index'] = i
        df['risk'] = risk
        df['cvss_vector'] = cvss_vector
        df['risk_reduction'] = 0.0  # Initialize column


        for idx, row in df.iterrows():
            strategy = row['strategies']  # Assuming this column exists in `df`
            tactic_rows = tactic_rows_by_strategy.get(strategy, [])

            if not tactic_rows:
                continue  # Skip if no tactic found

            adjustment_key = (cvss_vector, strategy)
            if adjustment_key not in adjustment_cache:
                adjustment_cache[adjustment_key] = adjust_cvss(cvss_vector, tactic_rows)
            new_vector, new_score = adjustment_cache[adjustment_key]

            if new_score is not None:
                risk_key = (i, new_vector)
                if risk_key not in risk_cache:
                    modified_incident = copy.deepcopy(incident_for_risk)
                    exploitability, impact = extract_exploitability_and_impact(new_vector)
                    modified_incident[i]['exploitability'] = exploitability
                    modified_incident[i]['impact'] = impact
                    risk_cache[risk_key] = calculate_risk(modified_incident)
                new_risk = risk_cache[risk_key]
                risk_reduction = risk - new_risk

                df.at[idx, 'risk_reduction'] = risk_reduction

        if not df.empty:
            dfs.append(df)

    if not dfs:
        return pd.DataFrame(columns=empty_columns), risk, risk

    combined_df = pd.concat(dfs, ignore_index=True)

    detection_df = combined_df[combined_df['def_tactic_label'] == 'Detect'] \
        .sort_values(by='risk_reduction', ascending=False, kind='mergesort').head(top_k)

    containment_df = combined_df[combined_df['def_tactic_label'] == 'Isolate'] \
        .sort_values(by='risk_reduction', ascending=False, kind='mergesort').head(top_k)

    eradication_df = combined_df[combined_df['def_tactic_label'] == 'Evict'] \
        .sort_values(by='risk_reduction', ascending=False, kind='mergesort').head(top_k)

    recovery_df = combined_df[combined_df['def_tactic_label'] == 'Restore'] \
        .sort_values(by='risk_reduction', ascending=False, kind='mergesort').head(top_k)

    
    selected_countermeasures_dfs = [detection_df, containment_df, eradication_df, recovery_df]

    selected_countermeasures = pd.concat(selected_countermeasures_dfs, ignore_index=True)
    dedup_columns = [
        'off_tech_id',
        'def_tech_label',
        'def_tactic_label',
        'def_artifact_label',
        'host',
        'step_index',
    ]
    selected_countermeasures = selected_countermeasures \
        .sort_values(by='risk_reduction', ascending=False, kind='mergesort') \
        .drop_duplicates(subset=dedup_columns, keep='first')

    candidates = []
    for _, row in selected_countermeasures.iterrows():
        try:
            step_index = int(row['step_index'])
        except (KeyError, TypeError, ValueError):
            continue
        tactic_rows = tactic_rows_by_strategy.get(row['strategies'], [])
        if not tactic_rows:
            continue
        adjustment_key = (row['cvss_vector'], row['strategies'])
        if adjustment_key not in adjustment_cache:
            adjustment_cache[adjustment_key] = adjust_cvss(row['cvss_vector'], tactic_rows)
        new_vector, new_score = adjustment_cache[adjustment_key]
        if new_score is None:
            continue
        exploitability, impact = extract_exploitability_and_impact(new_vector)
        if math.isnan(exploitability) or math.isnan(impact):
            continue
        candidates.append((step_index, new_vector, new_score, exploitability, impact))

    incident_copy = copy.deepcopy(incident_for_risk)
    epsilon = 1e-9
    for _ in range(max(1, 50 * len(candidates))):
        current_risk = calculate_risk(incident_copy)
        best_gain = epsilon
        best = None
        for candidate in candidates:
            step_index, _new_vector, _new_score, exploitability, impact = candidate
            step = incident_copy[step_index]
            saved = (step.get('exploitability'), step.get('impact'))
            step['exploitability'] = exploitability
            step['impact'] = impact
            gain = current_risk - calculate_risk(incident_copy)
            step['exploitability'], step['impact'] = saved
            if gain > best_gain:
                best_gain = gain
                best = candidate
        if best is None:
            break
        step_index, new_vector, new_score, exploitability, impact = best
        step = incident_copy[step_index]
        step['cvss_vector'] = new_vector
        step['cvss_score'] = new_score
        step['exploitability'] = exploitability
        step['impact'] = impact

    updated_risk = calculate_risk(incident_copy)

    return selected_countermeasures, risk, updated_risk
