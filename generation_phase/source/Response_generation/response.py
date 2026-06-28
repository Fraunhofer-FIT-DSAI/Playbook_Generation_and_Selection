import os
import sys
import xml.etree.ElementTree as ET
import graphviz
import xmltodict
import uuid
import random
from datetime import datetime, timezone
import networkx as nx
import matplotlib.pyplot as plt
import copy
from networkx.drawing.nx_pydot import graphviz_layout
import json
import extractDefenseKnowledge
import inflect
import textstat
import numpy as np
import nltk
import spacy
import pandas as pd
import seaborn as sns
from cvss import CVSS3
import time
import re
from def3nd.def3nd import get_results_by_attack_and_tactic  # Adjust the import path if needed


# Ensure required models are downloaded
#nltk.download('punkt')
#nlp = spacy.load("en_core_web_sm")

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Incident_generation.incidents import IncidentGenerator



root_dir = 'mulval-inputs'


class ResponseGenerator:
    def __init__(self, incidentGenerator, output_dir=None, limit=500):
        self.incidentGenerator = incidentGenerator
        self.incidents = incidentGenerator.get_incidents()
        self.attackTree = incidentGenerator.get_attack_tree()
        self.dir = self.incidentGenerator.get_directory()
        self.goal_based_incidents = incidentGenerator.get_goal_based_incidents()
        self.output_dir = output_dir or os.path.join(root_dir, self.dir, "generated_playbooks")
        self.limit = limit
        self.agent = self.generate_agent()
        self.responseMitigationLikelihood = {}
        self.initialRisks = []
        self.finalRisks = []
        self.average_risk_reduction = 0
        self.playbook_steps = []
        self.not_covered = 0

        self.detections_set = []
        self.containments_set = []
        self.eradications_set = []
        self.recoveries_set = []
        self.response_set = []

        self.tactic_df = pd.read_csv("Response_generation/defend_cvss.csv")

        self.generate_responses()

        #self.extract_countermeasures()

    def derive_countermeasures_sets(self, countermeasures):
        
        techniques = []
        detections = []
        containments = []
        eradications = []
        recoveries = []
        for index, row in countermeasures.iterrows():
            technique = row['def_tech_label']
            tactic = row['def_tactic_label']

            techniques.append(technique)

            if tactic == 'Detect':
                detections.append(technique)
            elif tactic == 'Isolate':
                containments.append(technique)
            elif tactic == 'Evict':
                eradications.append(technique)
            elif tactic == 'Restore':
                recoveries.append(technique)

        self.detections_set.append(detections)
        self.containments_set.append(containments)
        self.eradications_set.append(eradications)
        self.recoveries_set.append(recoveries)

        self.response_set.append(techniques)


    def plot_unique_counts(self, filename='unique_counts.png'):
        categories = ['Detection', 'Containment', 'Eradication', 'Recovery', 'Response']
        
        # Calculate unique counts (convert each inner list to tuple)
        unique_counts = [
            len(set(tuple(item) for item in self.detections_set)),
            len(set(tuple(item) for item in self.containments_set)),
            len(set(tuple(item) for item in self.eradications_set)),
            len(set(tuple(item) for item in self.recoveries_set)),
            len(set(tuple(item) for item in self.response_set))
        ]
        
        x = np.arange(len(categories))
        width = 0.6  # Wider bars since only one bar per category

        fig, ax = plt.subplots(figsize=(10, 6))
        rects = ax.bar(x, unique_counts, width, color='darkorange')

        ax.set_ylabel('Unique Count')
        ax.set_title('Unique Countermeasure Sets per Category')
        ax.set_xticks(x)
        ax.set_xticklabels(categories)

        # Add text labels above bars
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom')

        plt.tight_layout()

        # Save the plot
        os.makedirs('plots', exist_ok=True)
        plt.savefig(os.path.join('plots', filename))
        plt.show()
    def to_imperative(self, verb):
        # Handle common 3rd-person singular endings
        if verb.endswith('ies'):
            base = re.sub(r'ies$', 'y', verb)
        elif verb.endswith('es'):
            base = re.sub(r'es$', '', verb)
        elif verb.endswith('s'):
            base = re.sub(r's$', '', verb)
        else:
            base = verb

        return base.capitalize()
    
    def extract_countermeasures(self, strategies, label):
        owl_path = "Response_generation/def3nd/d3fend.owl"

        # Filter strategies based on the label
        filtered = [s for s in strategies if s[2] == label]

        #print(filtered)

        results = []

        for _, tactic_name, _, attack_pid, _ in filtered: 
            attack_id = str(attack_pid).split()[-1]
            tactic_class_name = tactic_name.replace(" ", "")  # Remove spaces
            tactic_results = get_results_by_attack_and_tactic(owl_path, attack_id, tactic_class_name)
            #print(results)
            results.append((tactic_name, tactic_results))  # Keep original name for context

        return results

    
    def extract_assets(self, node):
        return
    
    def generate_agent(self):
        return 'individual' + self.generate_id()
    

# Generate a random UUID (like 'fa16a4e9-e6b9-4658-b464-ca1632ff57f4') for workflows in playbooks
    def generate_id(self):
        unique_id = str(uuid.uuid4())  
        return f"--{unique_id}" 
    
    def generate_random_date(self, start, end):
    # Generate a random timestamp between start and end

        random_timestamp = random.uniform(start.timestamp(), end.timestamp())
        
        random_date = datetime.fromtimestamp(random_timestamp, tz=timezone.utc)

        return random_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'



    def generate_playbook_metadata(self, name):
        start_date = datetime(2023, 1, 1)
        end_date = datetime(2025, 1, 1)
        created_date = self.generate_random_date(start_date, end_date)
        created_date_obj = datetime.strptime(created_date[:-1], '%Y-%m-%dT%H:%M:%S.%f')
        modified_date = self.generate_random_date(created_date_obj, end_date)


        playbook = {}
        playbook['type'] = 'playbook'
        playbook['spec_version'] = 'cacao-2.0'
        playbook['id'] = 'playbook' + self.generate_id()
        playbook['name'] = name
        playbook['created_by'] = 'identity' + self.generate_id()
        playbook['created'] = created_date
        playbook['modified'] =  modified_date

        return playbook
    
    def get_variable(self, index, artifact):
        artifact = '_'.join(artifact.split())
        variable_name = '__attack_point' + str(index) + '_' + artifact + '__' 
        return variable_name
    
    def generate_playbook_preparation(self, incident, incident_index):
        playbook_variables = {}
        attack_points = self.incidentGenerator.get_attack_ids(incident_index)
        for index, attack_point in enumerate(attack_points):
            #fact = self.attackTree.nodes[attack_point].get('fact')
            #facts = fact.split()
            #attack_id = facts[-1][:-1]

            attack_id = attack_point
            attack_id = attack_id[1:]

            artifacts = extractDefenseKnowledge.get_artifacts(attack_id)

            for index_artifacts, row in artifacts.iterrows():
                artifact = row['off_artifact_label']

                artifact = '_'.join(artifact.split())

                variable_name = '__attack_point' + str(index) + '_' + artifact + '__' 
                variable = {}
                variable['type'] = 'boolean'
                variable['value'] = 'false'

                playbook_variables[variable_name] = variable

        return playbook_variables

    def generate_playbook_action(self, cmds, next, desc, statistics):
        statistics['stepsNum'] += 1
        if desc == 'Detection':
            statistics['detection']['stepsNum'] += 1
        elif desc == 'Containment':
            statistics['containment']['stepsNum'] += 1
        elif desc == 'Eradication':
            statistics['eradication']['stepsNum'] += 1

        action = {}
        action['type'] = 'action'
        action['description'] = desc
        action['commands'] = []
        for cmd in cmds:
            command = {}
            command['command'] = cmd
            command['type'] = 'manual'
            action['commands'].append(command)

        
        action['agent'] = self.agent
        
        if next == 'action' or next == 'while-condition' or next == 'if-condition' or next == 'end':
            on_completion = next + self.generate_id()
        else:
            on_completion = next
        action['on_completion'] = on_completion
        return action, on_completion

    def generate_playbook_if(self, condition, on_true_next, on_false_next, desc, statistics):

        statistics['stepsNum'] += 1
        if desc == 'Detection':
            statistics['detection']['stepsNum'] += 1
        elif desc == 'Containment':
            statistics['containment']['stepsNum'] += 1
        elif desc == 'Eradication':
            statistics['eradication']['stepsNum'] += 1

        if_condition = {}
        if_condition['type'] = 'if-condition'
        if_condition['description'] = desc
        if_condition['condition'] = condition
        if_condition['agent'] = self.agent
        if on_true_next == 'action' or on_true_next == 'while-condition' or on_true_next == 'if-condition':
            on_true = on_true_next + self.generate_id()
        else:
            on_true = on_true_next
        if on_false_next == 'action' or on_false_next == 'while-condition' or on_false_next == 'if-condition':
            on_false = on_false_next + self.generate_id()
        else:
            on_false = on_false_next

        if on_true_next != None:
            if_condition['on_true'] = on_true
        if on_false_next != None:
            if_condition['on_false'] = on_false

        return if_condition, on_true, on_false

    def generate_playbook_while(self, condition, on_true, on_complete, desc, statistics):
        while_condition = {}

        statistics['stepsNum'] += 1
        if desc == 'Detection':
            statistics['detection']['stepsNum'] += 1
        elif desc == 'Containment':
            statistics['containment']['stepsNum'] += 1
        elif desc == 'Eradication':
            statistics['eradication']['stepsNum'] += 1

        while_condition['type'] = 'while-condition'
        while_condition['description'] = desc
        while_condition['condition'] = condition
        while_condition['agent'] = self.agent
        on_true = on_true + self.generate_id()
        on_completion = on_complete + self.generate_id()
        while_condition['on_true'] = on_true
        while_condition['on_completion'] = on_completion

        return while_condition, on_true, on_completion
    

    def generate_simple_workflow(self, beginning_key, ending_key, statistics, countermeasures):
        actions = {}


        #print('Beginning Key: ', beginning_key)
        cur_action = beginning_key
    
        # Detections
        detections = countermeasures[countermeasures['def_tactic_label'] == 'Detect']
        detection_cmds = []
        for index, row in detections.iterrows():
            def_tech = row['def_tech_label']
            def_rel_artifact = row['def_artifact_rel_label']
            def_artifact = row['def_artifact_label']

            imperative_rel = self.to_imperative(def_rel_artifact)

            cmd = imperative_rel + ' ' + def_artifact + ' by the techniques ' + def_tech + '.'
            detection_cmds.append(cmd)

        detection_action, next_action = self.generate_playbook_action(detection_cmds, 'action', 'Detection', statistics)
        
        actions[cur_action] = detection_action
        cur_action = next_action

        
        # Containment
        containment = countermeasures[countermeasures['def_tactic_label'] == 'Isolate']
        containment_cmds = []
        for index, row in containment.iterrows():
            def_tech = row['def_tech_label']
            def_rel_artifact = row['def_artifact_rel_label']
            def_artifact = row['def_artifact_label']

            imperative_rel = self.to_imperative(def_rel_artifact)

            cmd = imperative_rel + ' ' + def_artifact + ' by the techniques ' + def_tech + '.'
            containment_cmds.append(cmd)
        
        containment_action, next_action = self.generate_playbook_action(containment_cmds, 'action', 'Containment', statistics)


        actions[cur_action] = containment_action
        cur_action = next_action


        # Eradication
        eradications = countermeasures[countermeasures['def_tactic_label'] == 'Evict']
        eradication_cmds = []
        for index, row in eradications.iterrows():
            def_tech = row['def_tech_label']
            def_rel_artifact = row['def_artifact_rel_label']
            def_artifact = row['def_artifact_label']

            imperative_rel = self.to_imperative(def_rel_artifact)

            cmd = imperative_rel + ' ' + def_artifact + ' by the techniques ' + def_tech + '.'
            eradication_cmds.append(cmd)
        
        eradication_action, next_action = self.generate_playbook_action(eradication_cmds, 'action', 'Eradication', statistics)


        actions[cur_action] = eradication_action
        cur_action = next_action


        # Recovery
        recoveries = countermeasures[countermeasures['def_tactic_label'] == 'Restore']
        recovery_cmds = []
        for index, row in recoveries.iterrows():
            def_tech = row['def_tech_label']
            def_rel_artifact = row['def_artifact_rel_label']
            def_artifact = row['def_artifact_label']

            imperative_rel = self.to_imperative(def_rel_artifact)

            cmd = imperative_rel + ' ' + def_artifact + ' by the techniques ' + def_tech + '.'
            recovery_cmds.append(cmd)
        
        recovery_action, next_action = self.generate_playbook_action(recovery_cmds, ending_key, 'Recovery', statistics)


        actions[cur_action] = recovery_action
        cur_action = next_action

        return actions

    
    def generate_playbook_detection(self, incident, incident_index, while_id, statistics, strategies):
        actions = {}

        condition = 'Is new evidence of compromisation found?'
        compromisation_loop, on_true, on_while_completion = self.generate_playbook_while(condition, 'action', 'if-condition', 'Detection', statistics) 

        cur_action = on_true

        #get the list of countermeasures here
        #what do you need for it? strategies
        #1- pass the strategies to the function
        #2- call the function countermeasures, you need to retrieve the detections, and containments

        detection_countermeasures = self.extract_countermeasures(strategies, 'Detect')
        containment_countermeasures = self.extract_countermeasures(strategies, 'Isolate')

        #print(detection_countermeasures)
        #print(containment_countermeasures)
        attack_points = self.incidentGenerator.get_attack_ids(incident_index)
        for index, attack_point in enumerate(attack_points):
            #fact = self.attackTree.nodes[attack_point].get('fact')
            #facts = fact.split()
            #attack_id = facts[-1][:-1]

            attack_id = attack_point

            attack_id = attack_id[1:]
            
            artifacts = extractDefenseKnowledge.get_artifacts(attack_id)

            name = ''

            for index, row in artifacts.iterrows():
                attack_technique = row['off_tech_label']
                artifact = row['off_artifact_label']
                artifact_rel = row['off_artifact_rel_label']
                artifact_rel = artifact_rel[:-1] #for making the verb imperative
                #artifact_rel_past = conjugate(artifact_rel, tense=PAST)


                artifact_detections = extractDefenseKnowledge.get_detections_by_artifact(attack_id, artifact)
                artifact_containments = extractDefenseKnowledge.get_containments_by_artifact(attack_id, artifact)

                detectio_countermeasures = self.extract_countermeasures(strategies, 'Detect')

                if not artifact_detections.empty:
                    name = 'Check if ' + attack_technique + artifact_rel + ' the ' + artifact
                    detection_cmds = []
                    for detection_index, detection_row in artifact_detections.iterrows():
                        def_tech = detection_row['def_tech_label']
                        def_rel_artifact = detection_row['def_artifact_rel_label']
                        def_rel_artifact = def_rel_artifact.capitalize()
                        def_rel_artifact = def_rel_artifact[:-1] #for making the verb imperative
                        cmd = def_rel_artifact + ' ' + artifact + ' by the technique ' + def_tech
                        detection_cmds.append(cmd)
                        statistics['detection']['countermeasures'].append(def_tech)
                        statistics['detection']['texts'].append(cmd) 
                    artifact_action, next_action = self.generate_playbook_action(detection_cmds, 'if-condition', 'Detection', statistics)
                    actions[cur_action] = artifact_action
                    cur_action = next_action
                    
                    condition = attack_technique + ' ' + artifact_rel + ' ' + artifact + '?' 
                    artifact_is_detected_action = ''
                    on_true = ''
                    on_false = ''
                    if index == artifacts.index[-1]:    
                        artifact_is_detected_action, on_true, on_false = self.generate_playbook_if(condition, 'action', while_id, 'Detection', statistics)
                    else:
                        artifact_is_detected_action, on_true, on_false = self.generate_playbook_if(condition, 'action', 'action', 'Detection', statistics)
                    actions[cur_action] = artifact_is_detected_action
                    cur_action = on_true
                    containment_cmds = []
                    variable = self.get_variable(incident_index, artifact)
                    variable_cmd = variable + '.value = true'
                    if not artifact_containments.empty:
                        containment_cmds.append(variable_cmd)
                        for containment_index, containment_row in artifact_containments.iterrows():
                            def_tech = containment_row['def_tech_label']
                            def_rel_artifact = containment_row['def_artifact_rel_label']
                            def_rel_artifact = def_rel_artifact.capitalize()
                            def_rel_artifact = def_rel_artifact[:-1] #for making the verb imperative
                            cmd = def_rel_artifact + ' ' + artifact + ' by the technique ' + def_tech
                            containment_cmds.append(cmd)
                            statistics['containment']['countermeasures'].append(def_tech)
                            statistics['containment']['texts'].append(cmd) 
                    containment_action = ''
                    next_action = ''
                    if containment_cmds:
                        if index == artifacts.index[-1]:
                            containment_action, next_action = self.generate_playbook_action(containment_cmds, while_id, 'Containment', statistics)
                        else:
                            containment_action, next_action = self.generate_playbook_action(containment_cmds, on_false, 'Containment', statistics)
                        actions[cur_action] = containment_action
                    cur_action = on_false



        return actions, compromisation_loop, on_while_completion

    def generate_playbook_eradication(self, incident, incident_index, cur_action, while_id, statistics):
        actions = {}
        attack_points = self.incidentGenerator.get_attack_ids(incident_index)
        for index, attack_point in enumerate(attack_points):
            #fact = self.attackTree.nodes[attack_point].get('fact')
            #facts = fact.split()
            #attack_id = facts[-1][:-1]

            attack_id = attack_point

            attack_id = attack_id[1:]
            artifacts = extractDefenseKnowledge.get_artifacts(attack_id)

            name = ''

            for index, row in artifacts.iterrows():
                attack_technique = row['off_tech_label']
                artifact = row['off_artifact_label']
                artifact_rel = row['off_artifact_rel_label']
                artifact_rel = artifact_rel[:-1] #for making the verb imperative


                artifact_eradications = extractDefenseKnowledge.get_eradications_by_artifact(attack_id, artifact)

                if not artifacts.empty:
                    variable = self.get_variable(incident_index, artifact)
                    condition = variable + '.value == true'
                    if_condition, on_true, on_false = self.generate_playbook_if(condition, 'action', 'if-condition', 'Eradication', statistics)

                    actions[cur_action] = if_condition
                    cur_action = on_true

                
                    eradication_cmds = []
                    for eradication_index, eradication_row in artifact_eradications.iterrows():
                        def_tech = eradication_row['def_tech_label']
                        def_rel_artifact = eradication_row['def_artifact_rel_label']
                        def_rel_artifact = def_rel_artifact.capitalize()
                        def_rel_artifact = def_rel_artifact[:-1] #for making the verb imperative
                        cmd = def_rel_artifact + ' ' + artifact + ' by the technique ' + def_tech
                        eradication_cmds.append(cmd)
                        statistics['eradication']['countermeasures'].append(def_tech)
                        statistics['eradication']['texts'].append(cmd) 
                    if eradication_cmds:
                        if index == artifacts.index[-1]:
                            eradication_action, next_action = self.generate_playbook_action(eradication_cmds, while_id, 'Eradication', statistics)
                        else:
                            eradication_action, next_action = self.generate_playbook_action(eradication_cmds, on_false, 'Eradication', statistics)
                        actions[cur_action] = eradication_action
                    cur_action = on_false

        last_key = list(actions.keys())[-1]
        actions[last_key]['on_completion'] = while_id   
        return actions


    def generate_playbook_start(self, name):
        key = 'start' + self.generate_id()
        val = {}
        val['type'] = 'start'
        val['name'] = 'Start playbook ' + name
        on_completion = 'while-condition' + self.generate_id()
        val['on_completion'] = on_completion

        return key, val, on_completion

    def generate_workflow(self, name, incident, index, statistics, countermeasures):
        workflow = {}
        workflow_start_key = ''
        workflow_analyze_start_key = ''
        workflow_detection_start_key = ''


        
        workflow_start_key, workflow_start_val, workflow_eradication_while_key = self.generate_playbook_start(name)


        workflow[workflow_start_key] = workflow_start_val

        eradication_condition = 'Threat detected?'
        workflow_eradication_val, workflow_detection_while_key, end_key = self.generate_playbook_while(eradication_condition, 'action', 'end', 'Eradication', statistics)


        #workflow_detection_val, compromisation_loop, eradication_start_key = self.generate_playbook_detection(incident, index, workflow_detection_while_key, statistics, countermeasures)


        workflow[workflow_eradication_while_key] = workflow_eradication_val

        #workflow[workflow_detection_while_key] = compromisation_loop



        #for key, value in workflow_detection_val.items():
        #    if key != workflow_detection_while_key:
        #        workflow[key] = value

        workflow_simple = self.generate_simple_workflow(workflow_detection_while_key, workflow_eradication_while_key, statistics, countermeasures)

        for key, value in workflow_simple.items():
            workflow[key] = value


        #eradications = self.generate_playbook_eradication(incident, index, eradication_start_key, workflow_eradication_while_key, statistics)

        #for key, value in eradications.items():
        #    if key != workflow_detection_while_key:
        #        workflow[key] = value


        


        end_action = {}
        end_action['type'] = 'end'
        end_action['name'] = 'End of playbook ' + name
        workflow[end_key] = end_action

        return workflow, workflow_start_key
    
    def initStatistics(self, incident, incident_name):
        statistics = {}
        statistics['title'] = 'Statistics for incident ' + incident_name
        statistics['stepsNum'] = 0
        statistics['readability'] = 0
        statistics['actionability'] = 0
        statistics['artifacts'] = []
        detection = {}
        containment = {}
        eradication = {}

        detection['stepsNum'] = 0
        detection['readability'] = {}
        detection['actionability'] = {}
        detection['countermeasures'] = []
        detection['texts'] = []
        #detection['artifacts'] = []

        containment['stepsNum'] = 0
        containment['readability'] = {}
        containment['actionability'] = {}
        containment['countermeasures'] = []
        containment['texts'] = []
        #containment['artifacts'] = []

        eradication['stepsNum'] = 0
        eradication['readability'] = {}
        eradication['actionability'] = {}
        eradication['countermeasures'] = []
        eradication['texts'] = []
        #eradication['artifacts'] = []

        statistics['detection'] = detection
        statistics['containment'] = containment
        statistics['eradication'] = eradication

        return statistics

    def calculate_actionability(self, command_list):
        actionability_scores = []

        for command in command_list:
            doc = nlp(command)

            # Heuristic checks for actionability
            starts_with_verb = doc[0].pos_ == "VERB"
            has_object = any(tok.dep_ in ("dobj", "pobj") for tok in doc)
            length_ok = len(command.split()) <= 15
            passive_voice = any(tok.dep_ == "auxpass" for tok in doc)

            # Assign weights (tweakable)
            score = (
                0.4 * starts_with_verb +
                0.3 * has_object +
                0.2 * length_ok +
                0.1 * (not passive_voice)
            )

            actionability_scores.append(round(score, 2))

        # Calculate average actionability score for the list
        average_actionability = sum(actionability_scores) / len(actionability_scores) if actionability_scores else 0
        return round(average_actionability, 2)
    
    def plot_response_statistics(self, statistics):
        data = {
        "Phase": ["Detection", "Containment", "Eradication", "Total"],
        "Steps": [
            statistics['detection']['stepsNum'],
            statistics['containment']['stepsNum'],
            statistics['eradication']['stepsNum'],
            statistics['stepsNum']
        ]
        }

        # Convert to DataFrame for seaborn
        df = pd.DataFrame(data)

        # Set Seaborn style
        sns.set(style="whitegrid", context="notebook", font_scale=1.2)

        # Set custom color palette
        palette = sns.color_palette("Set2")

        # Create barplot
        plt.figure(figsize=(9, 6))
        ax = sns.barplot(data=df, x="Phase", y="Steps", palette=palette)

        # Add value labels on top of bars
        for container in ax.containers:
            ax.bar_label(container, fmt='%d', label_type='edge', padding=3)

        # Customize plot
        ax.set_title("Number of Steps per Response Phase", fontsize=16, weight='bold')
        ax.set_ylabel("Number of Steps")
        ax.set_xlabel("Response Phase")
        ax.set_ylim(0, max(df["Steps"]) + 5)

        sns.despine()  # remove top and right borders
        plt.tight_layout()
        plt.savefig("plots/step_numbers.png", dpi=300)
        plt.show()

            # Extract number of countermeasures from each phase
        detection_count = len(statistics['detection']['countermeasures'])
        containment_count = len(statistics['containment']['countermeasures'])
        eradication_count = len(statistics['eradication']['countermeasures'])
        total_count = detection_count + containment_count + eradication_count

        # Prepare data
        data = {
            "Phase": ["Detection", "Containment", "Eradication", "Total"],
            "Countermeasures": [detection_count, containment_count, eradication_count, total_count]
        }

        df = pd.DataFrame(data)

        # Set seaborn style
        sns.set(style="whitegrid", context="notebook", font_scale=1.2)

        # Plot
        plt.figure(figsize=(9, 6))
        ax = sns.barplot(data=df, x="Phase", y="Countermeasures", palette="pastel")

        # Add value labels
        for container in ax.containers:
            ax.bar_label(container, fmt='%d', label_type='edge', padding=3)

        # Customize
        ax.set_title("Number of Countermeasures per Phase", fontsize=16, weight='bold')
        ax.set_ylabel("Number of Countermeasures")
        ax.set_xlabel("Response Phase")
        ax.set_ylim(0, max(df["Countermeasures"]) + 3)

        sns.despine()
        plt.tight_layout()
        plt.savefig("plots/countermeasure_numbers.png", dpi=300)
        plt.show()

        # Extract actionability scores (assumed float values)
        detection_score = statistics['detection']['actionability']
        containment_score = statistics['containment']['actionability']
        eradication_score = statistics['eradication']['actionability']
        avg_score = (detection_score + containment_score + eradication_score) / 3

        # Prepare data
        data = {
            "Phase": ["Detection", "Containment", "Eradication", "Average"],
            "Actionability": [detection_score, containment_score, eradication_score, avg_score]
        }

        df = pd.DataFrame(data)

        # Seaborn style
        sns.set(style="whitegrid", context="notebook", font_scale=1.2)

        # Plot
        plt.figure(figsize=(9, 5))
        ax = sns.barplot(data=df, x="Phase", y="Actionability", palette="deep")

        # Add value labels
        for container in ax.containers:
            ax.bar_label(container, fmt='%.2f', label_type='edge', padding=3)

        # Customize
        ax.set_title("Actionability Score per Phase", fontsize=16, weight='bold')
        ax.set_ylabel("Actionability Score")
        ax.set_xlabel("Response Phase")
        ax.set_ylim(0, max(df["Actionability"]) + 0.1)

        sns.despine()
        plt.tight_layout()
        plt.savefig("plots/actionability_scores.png", dpi=300)
        plt.show()

        # Extract individual readability metrics
        detection_read = statistics['detection']['readability']
        containment_read = statistics['containment']['readability']
        eradication_read = statistics['eradication']['readability']

        # Compute average readability score per phase
        detection_avg = sum(detection_read.values()) / len(detection_read)
        containment_avg = sum(containment_read.values()) / len(containment_read)
        eradication_avg = sum(eradication_read.values()) / len(eradication_read)

        # Add average to each readability dict
        detection_read["Average"] = detection_avg
        containment_read["Average"] = containment_avg
        eradication_read["Average"] = eradication_avg

        # Create DataFrame
        df = pd.DataFrame({
            'Metric': list(detection_read.keys()),
            'Detection': list(detection_read.values()),
            'Containment': list(containment_read.values()),
            'Eradication': list(eradication_read.values())
        })

        # Melt for grouped barplot
        df_melted = df.melt(id_vars='Metric', var_name='Phase', value_name='Score')

        # Plot
        plt.figure(figsize=(10, 6))
        sns.set(style="whitegrid", context="notebook", font_scale=1.1)
        ax = sns.barplot(data=df_melted, x='Metric', y='Score', hue='Phase', palette='colorblind')

        # Add labels
        for container in ax.containers:
            ax.bar_label(container, fmt='%.1f', padding=3)

        # Customize
        plt.title("Readability Metrics per Response Phase (with Average)", fontsize=16, weight='bold')
        plt.xlabel("Readability Metric")
        plt.ylabel("Score")
        plt.xticks(rotation=15)
        plt.legend(title="Phase")
        plt.tight_layout()
        sns.despine()
        plt.savefig("plots/readability_scores.png", dpi=300)
        plt.show()
        return

        
    def escalate(self, val):
        """Escalate N → L → H"""
        cvss_scale = ['N', 'L', 'H']
        try:
            idx = cvss_scale.index(val)
            return cvss_scale[min(idx + 1, 2)]
        except ValueError:
            return val

    def deescalate(self, val):
        """Deescalate H → L → N"""
        cvss_scale = ['N', 'L', 'H']
        try:
            idx = cvss_scale.index(val)
            return cvss_scale[max(idx - 1, 0)]
        except ValueError:
            return val

    def adjust_cvss(self, cvss_vector: str, tactic_data: pd.DataFrame) -> tuple[str, float]:
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
                    vector_dict[metric] = 'R'
                    continue

                current_val = vector_dict.get(metric)
                if current_val not in cvss_scale:
                    continue

                if adjustment == 'High':
                    vector_dict[metric] = self.escalate(current_val)
                elif adjustment == 'Low':
                    vector_dict[metric] = self.deescalate(current_val)

        # Reconstruct vector (preserve original ordering)
        new_vector = "CVSS:3.1/" + "/".join([f"{k}:{v}" for k, v in vector_dict.items()])

        try:
            new_score = CVSS3(new_vector).base_score
        except Exception as e:
            #print(f"Error computing score: {e}")
            new_score = None

        return new_vector, new_score

    def calculate_risk(self, incident):
        total_risk = 0.0
        cumulative_exploitability = 1.0
        cumulative_impact = 0.0

        for step in incident:
            exploitability = step.get('exploitability', 0.0)
            impact = step.get('impact', 0.0)

            cumulative_exploitability *= float(exploitability) / 10
            cumulative_impact += float(impact)

            risk_i = cumulative_exploitability * cumulative_impact
            total_risk += risk_i

        return total_risk

    def extract_exploitability_and_impact(self, vector):
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
    
    def plot_risks(self, risks, save_path_risks="risk_over_iterations.png"):
        import matplotlib.pyplot as plt
        import seaborn as sns
        import numpy as np

        # Normalize the risks to a 0–10 scale
        risks = np.array(risks)
        min_risk = risks.min()
        max_risk = risks.max()
        
        if max_risk != min_risk:
            normalized_risks = (risks - min_risk) / (max_risk - min_risk) * 10
        else:
            normalized_risks = np.full_like(risks, 5)  # default to mid if all values are same

        # Plot aesthetics
        sns.set(style="whitegrid", context="notebook")
        iterations = np.arange(len(normalized_risks))
        
        plt.figure(figsize=(10, 6))
        color = sns.color_palette("coolwarm")[4]

        # Plot normalized risks
        plt.plot(iterations, normalized_risks, marker='o', linestyle='-', color=color,
                linewidth=2.5, markersize=7, markerfacecolor='white', markeredgewidth=2)

        # Annotate final value
        plt.text(iterations[-1], normalized_risks[-1] + 0.2, f"{normalized_risks[-1]:.2f}",
                fontsize=11, ha='center', fontweight='bold', color='black')

        # Labels and title
        plt.title("Normalized Risk Over Iterations", fontsize=18, fontweight='bold')
        plt.xlabel("Iteration", fontsize=14, fontweight='bold')
        plt.ylabel("Normalized Risk (0–10)", fontsize=14, fontweight='bold')
        plt.xticks(fontsize=12)
        plt.yticks(fontsize=12)
        plt.ylim(0, 10.5)

        # Add grid
        plt.grid(True, linestyle='--', linewidth=0.7, alpha=0.6)
        plt.tight_layout()

        # Save and show
        plt.savefig(save_path_risks, dpi=300, bbox_inches='tight')
        plt.show()

    def calculate_risk_reduction_percentage(self, save_path="risk_reduction_distribution.png"):
        self.risk_reduction_percentages = []

        for initial, final in zip(self.initialRisks, self.finalRisks):
            if initial == 0:
                reduction = 0.0  # You can also choose to skip or log this
            else:
                reduction = ((initial - final) / initial) * 100
            self.risk_reduction_percentages.append(reduction)

        self.average_risk_reduction = sum(self.risk_reduction_percentages) / len(self.risk_reduction_percentages)

        # Line plot with incident index on x-axis
        plt.figure(figsize=(10, 6))
        plt.plot(self.risk_reduction_percentages, marker='o', linestyle='-', color='teal')
        plt.title('Risk Reduction per Incident')
        plt.xlabel('Incident Index')
        plt.ylabel('Risk Reduction (%)')
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(save_path)
        plt.close()

    def total_risks_plot(self, save_path_comparison="initial_vs_final_risks.png"):
        # Second Plot: Initial vs Final Risks
        plt.figure(figsize=(8, 5))
        plt.plot(range(len(self.initialRisks)), self.initialRisks, label="Initial Risks", color=sns.color_palette("Reds")[2], linestyle='-', marker='o', markersize=8, linewidth=2)
        plt.plot(range(len(self.finalRisks)), self.finalRisks, label="Final Risks", color=sns.color_palette("Greens")[2], linestyle='-', marker='s', markersize=8, linewidth=2)
        plt.title("Initial vs Final Risks", fontsize=16, weight='bold')
        plt.xlabel("Index", fontsize=14)
        plt.ylabel("Risk Value", fontsize=14)
        plt.legend(fontsize=12, loc="best")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(save_path_comparison)
        plt.show()  # Show the second plot

    def total_risks_plot1(self, save_path_comparison="plots/initial_vs_final_risks_sample.png"):
        import numpy as np
        import matplotlib.pyplot as plt
        import seaborn as sns

        # Combine both for consistent normalization
        all_risks = np.array(self.initialRisks + self.finalRisks)
        min_risk = np.min(all_risks)
        max_risk = np.max(all_risks)

        if max_risk != min_risk:
            normalize = lambda x: (np.array(x) - min_risk) / (max_risk - min_risk) * 10
        else:
            normalize = lambda x: np.full_like(x, 5)

        norm_initial = normalize(self.initialRisks)
        norm_final = normalize(self.finalRisks)

        # Subsample every 50 points
        step = 50
        x_vals = np.arange(len(norm_initial))[::step]

        # Plot
        plt.figure(figsize=(12, 6))
        sns.set(style="whitegrid", context="notebook")

        plt.plot(x_vals, norm_initial[::step], label="Initial Risks",
                linestyle='None', marker='o', color='red', markersize=4)

        plt.plot(x_vals, norm_final[::step], label="Final Risks",
                linestyle='None', marker='s', color='green', markersize=4)

        # Labels and styling
        plt.title("Subsampled Scatter Plot of Normalized Initial vs Final Risks", fontsize=18, fontweight='bold')
        plt.xlabel("Index", fontsize=14, fontweight='bold')
        plt.ylabel("Normalized Risk (0–10)", fontsize=14, fontweight='bold')
        plt.xticks(fontsize=12)
        plt.yticks(fontsize=12)
        plt.ylim(0, 10.5)
        plt.legend(fontsize=12, loc="best")
        plt.grid(True, linestyle='--', linewidth=0.7, alpha=0.6)
        plt.tight_layout()

        # Save and show
        plt.savefig(save_path_comparison, dpi=300, bbox_inches='tight')
        plt.show()


    def calculate_jaccard(self):
        """
        Calculate average pairwise Jaccard distances for techniques, assets, and vulnerabilities.

        Returns:
            tuple of floats: (techniques_jaccard_avg, assets_jaccard_avg, vulns_jaccard_avg)
        """

        def avg_jaccard(sets_list):
            n = len(sets_list)
            sets = [set(s) for s in sets_list]
            distances = []
            for i in range(n):
                for j in range(i + 1, n):
                    a, b = sets[i], sets[j]
                    union = len(a | b)
                    intersection = len(a & b)
                    jd = 1 - (intersection / union) if union else 0.0
                    distances.append(jd)
            return sum(distances) / len(distances) if distances else 0.0

        response_jaccard = avg_jaccard(self.response_set)

        return response_jaccard



    def select_countermeasures(self, incident):
        num_iterations = 3  # You can change this as needed
        risks = []

        #print(incident)
        selected_pairs = set()
        final_results = []

        # Initial risk
        current_risk = self.calculate_risk(incident)
        self.initialRisks.append(current_risk)
        risks.append(current_risk)
        #print(f"Initial total risk: {current_risk:.4f}")

        for iteration in range(1, num_iterations + 1):
            best_pair = None
            max_risk_reduction = None
            best_score = None
            best_new_risk = None

            for i, step in enumerate(incident):
                host = step['host']
                original_vector = step['cvss_vector']
                attack_id = step['mitre']

                for _, tactic_row in self.tactic_df.iterrows():
                    tactic_name = tactic_row.get('def_tactic')
                    # This is the line I added
                    tactic_label = tactic_row.get('def_tactic_label')

                    if (host, tactic_name, tactic_label, attack_id) in selected_pairs:
                        continue  # Skip already used (host, tactic) pairs

                    new_vector, new_score = self.adjust_cvss(original_vector, pd.DataFrame([tactic_row]))

                    if new_score is not None:
                        # Create a modified incident copy to evaluate risk impact
                        modified_incident =copy.deepcopy(incident)
                        
                        exploitability, impact = self.extract_exploitability_and_impact(new_vector)
                        modified_incident[i]['exploitability'] = exploitability
                        modified_incident[i]['impact'] = impact

                        new_risk = self.calculate_risk(modified_incident)
                        risk_reduction = current_risk - new_risk

                        if max_risk_reduction is None or risk_reduction > max_risk_reduction:
                            max_risk_reduction = risk_reduction
                            best_pair = (host, tactic_name, tactic_label, attack_id)
                            best_score = new_score
                            best_index = i
                            best_new_vector = new_vector
                            best_new_risk = new_risk
                            


            if best_pair:
                selected_pairs.add(best_pair)
                final_results.append((*best_pair, best_score))
                risks.append(best_new_risk)

                # Apply the best tactic to the incident for the next iteration
                incident[best_index]['cvss_vector'] = best_new_vector
                current_risk -= max_risk_reduction

                # Print detailed info for this iteration
                #print(f"\nIteration {iteration}:")
                #print(f"  Selected Pair   : Host = {best_pair[0]}, Tactic = {best_pair[1]}")
                #print(f"  New CVSS Score  : {best_score:.1f}")
                #print(f"  New Total Risk  : {best_new_risk:.4f}")
                #print(f"  Risk Reduction  : {max_risk_reduction:.4f}")

        self.finalRisks.append(risks[-1])

        final_risk = risks[-1]
        #print(f"Final total risk: {final_risk:.4f}")

        #print("\nFinal selected countermeasures:")
        #for host, tactic, score in final_results:
        #    print(f"Host: {host}, Tactic: {tactic}, CVSS Score: {score:.1f}")

        #self.plot_risks(risks)

        #print(final_results)
        return final_results
    def create_incident(self):
        incident = []
        sequence = {}

        sequence['host'] = 'host9'
        sequence['cvss'] = 7.8
        sequence['cve'] = 'CVE-2021-3438'
        sequence['mitre'] = 'Exploitation for Privilege Escalation - T1068'
        sequence['exploitability'] = 1.8
        sequence['impact'] = 5.9
        sequence['cvss_vector'] = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
        incident.append(sequence)
 

        sequence['host'] = 'host8'
        sequence['mitre'] = 'Unsecured Credentials - T1552'
        sequence['cve'] = 'CVE-2022-0019'
        sequence['cvss'] = 7.5
        sequence['exploitability'] = 1.0
        sequence['impact'] = 3.6
        sequence['cvss_vector'] = 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N'
        incident.append(sequence)


        sequence['host'] = 'host7'
        sequence['mitre'] = 'File and Directory Discovery - T1083'
        sequence['cve'] = 'CVE-2021-3374'
        sequence['cvss'] = 5.5
        sequence['exploitability'] = 3.9
        sequence['impact'] = 1.4
        sequence['cvss_vector'] = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
        incident.append(sequence)



        sequence['host'] = 'host1'
        sequence['mitre'] = 'Hijack Execution Flow - T1574'
        sequence['cve'] = 'CVE-2020-5254'
        sequence['cvss'] = 6.1
        sequence['exploitability'] = 0.8
        sequence['impact'] = 2.7
        sequence['cvss_vector'] = 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N'
        incident.append(sequence)

        return incident
    
    def calculate_risk_reduction(self):
        if not self.initialRisks or not self.finalRisks:
            raise ValueError("Risk lists must not be empty.")

        if len(self.initialRisks) != len(self.finalRisks):
            raise ValueError("Initial and final risk lists must be of the same length.")

        total_reduction = 0
        count = 0

        for initial, final in zip(self.initialRisks, self.finalRisks):
            if initial == 0:
                continue  # Skip to avoid division by zero
            reduction = ((initial - final) / initial) * 100
            total_reduction += reduction
            count += 1

        if count == 0:
            return 0.0  # Avoid division by zero in average

        average_reduction = total_reduction / count
        return average_reduction


    def calculate_coverage(self, countermeasures):
        self.playbook_steps.append(len(countermeasures))


        phases = ['Detect', 'Isolate', 'Evict', 'Restore']

        
        for phase in phases:
            phase_df = countermeasures[countermeasures['def_tactic_label'] == phase]
            if phase_df.empty:
                self.not_covered += 1
                return
        
             
    def generate_responses(self):
        countermeasure_start_time = time.time()
        processed_count = 0
        os.makedirs(self.output_dir, exist_ok=True)
        for index, incident in enumerate(self.goal_based_incidents):
            if self.limit is not None and processed_count >= self.limit:
                break
            incident_name = 'Incident' + str(index)
            #example_incident = self.create_incident()
            #example_strategies = self.select_countermeasures(example_incident)
            #print(example_strategies)
            #break
            countermeasures, initial_risk, final_risk  = extractDefenseKnowledge.create_countermeasure_table(incident)
            self.derive_countermeasures_sets(countermeasures)
            self.calculate_coverage(countermeasures)
            #print(countermeasures)
            #print(initial_risk)
            #print(final_risk)
            #print(countermeasures)
            self.initialRisks.append(initial_risk)
            self.finalRisks.append(final_risk)
            statistics = []
            statistics = self.initStatistics(incident, incident_name)
            playbook = self.generate_playbook_metadata(incident_name)
            
            json_str = countermeasures.to_json(orient='records', indent=2)

            #print(json_str)
            #variables = self.generate_playbook_preparation(incident, index)
            #playbook['playbook_variables'] = variables
            workflow, workflow_start_key = self.generate_workflow(incident_name, incident, index, statistics, countermeasures)
            #print(workflow)
            playbook['workflow_start'] = workflow_start_key
            playbook['workflow'] = workflow
            #print(statistics)
            #self.calculateStatistics(statistics)

            file_path = os.path.join(self.output_dir, f"{incident_name}.json")
            with open(file_path, 'w') as f:
                json.dump(playbook, f, indent=4)
            processed_count += 1

        countermeasure_end_time = time.time()
        countermeasure_time = countermeasure_end_time - countermeasure_start_time
        #print(countermeasure_time)
        #self.calculate_risk_reduction_percentage()
        #print('Average Percent of risk reduction: ', self.average_risk_reduction)
        #self.total_risks_plot1()
        #self.plot_unique_counts()
        #print(self.calculate_jaccard())

        if not self.playbook_steps:
            print('No playbooks were generated.')
            return

        steps_no = sum(self.playbook_steps) / len(self.playbook_steps)
        coverage_denominator = processed_count or len(self.goal_based_incidents)

        print('Step No.: ', steps_no)
        print('Not Coverage Rate: ', self.not_covered / coverage_denominator)
        print('Risk Reduction Percentage: ', self.calculate_risk_reduction())
            
        return
    


# Example usage
if __name__ == "__main__":
    directories = [d for d in os.listdir(root_dir) if os.path.isdir(os.path.join(root_dir, d))]

    incidentGenerators = []

    incidentsNum = 0

    for dir in directories:
        if dir == 'NewTest':
            incidentGenerator = IncidentGenerator(dir)
            print('Number of incident:', incidentGenerator.get_incidents_num())
            #incidentGenerator.print_incidents()
            responseGenerator = ResponseGenerator(incidentGenerator)
            #incidentsNum += incidentGenerator.get_incidents_num()
        #print(incidentGenerator.get_incidents_average_length())

    #print(incidentsNum)
