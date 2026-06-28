import os
import csv
import xml.etree.ElementTree as ET
import graphviz
import xmltodict
import uuid
import random
from datetime import datetime, timedelta
import networkx as nx
import matplotlib.pyplot as plt
import copy
from networkx.drawing.nx_pydot import graphviz_layout
import json
from collections import deque
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from collections import Counter
import requests
import pandas as pd
import time
from collections import Counter
import math






root_dir = 'mulval-inputs'


class IncidentGenerator:
    def __init__(self, directory):
        self.directory = directory
        self.attackGraph = None # This is for the format that MulVal outputs
        self.attackTree = None  # This is for the format that I convert 
        self.incidents = []
        self.goalNodes = []
        self.attackerNodes = []
        self.averageIncidentLengh = 0
        self.goal_based_incidents = []
        self.cvsss = []
        self.unique_techniques = []
        self.diverse_techniques_all = 0
        self.lengths = []
        self.avg_cvss = 0
        self.incidentsNum = 0
        self.unique_techniques_num = 0
        cve_table_path = os.getenv("CVE_MITRE_ENRICHED_PATH", 'Incident_generation/CVE_MITRE_enriched.csv')
        self.mitre_cve_df = pd.read_csv(cve_table_path)
        self.techniques_set = []
        self.assets_set = []
        self.vulns_set = []
        self.incident_set = []

    
        self.read_attack_graph_file()
        self.convert_to_graphviz()
        self.find_goal_and_attacker_nodes()
        self.generate_incidents()
        self.convert_rules_to_goals()
        self.print_random_incidents()
        self.calculate_scenario_statistics()

    def get_directory(self):
        return self.directory
    
    def get_attack_graph(self):
        return self.attackGraph
    
    def get_attack_tree(self):
        return self.attackTree
    
    def get_incidents(self):
        return self.incidents
    
    def get_incidents_num(self):
        return self.incidentsNum if self.incidentsNum else len(self.incidents)
    
    def get_incidents_average_length(self):
        return self.averageIncidentLengh / 2
    
    def get_avg_cvss(self):
        return self.avg_cvss
    
    def get_unique_techniques_num(self):
        return self.diverse_techniques_all
    
    def get_goal_based_incidents(self):
        return self.goal_based_incidents
    
    def get_attack_ids(self, index):
        attack_ids = []
        incident = self.goal_based_incidents[index]
        for sequence in incident:
            attack_technique = sequence['mitre']
            if '-' in attack_technique:
                attack_id = attack_technique.rsplit('-', 1)[1].strip().split()[0]
            else:
                attack_id = attack_technique.strip().split()[-1]
            attack_ids.append(attack_id)

        return attack_ids


    def print_incidents(self):
        for index, incident in enumerate(self.incidents):
            attack_points = []
            for attack_point in incident:
                fact = self.attackTree.nodes[attack_point].get('fact')
                attack_points.append(fact)
            print('This is the incident ', index, ': ', attack_points)
    
    def read_attack_graph_file(self):
        """Reads AttackGraph.xml file from the directory and parses it."""
        full_path = os.path.join(root_dir, self.directory)  # Construct the full path

        for subdir, _, files in os.walk(full_path):
            for file in files:
                
                if file == "AttackGraph.xml":
                    file_path = os.path.join(subdir, file)
                    
                    # Read the content of the XML file
                    try:
                        tree = ET.parse(file_path)
                        root = tree.getroot()
                        
                        # Store the XML content in the dictionary with the directory name as key
                        dir_name = os.path.basename(subdir)
                        tree_string = ET.tostring(root, encoding="unicode")
                        self.attackGraph = xmltodict.parse(tree_string)
                    
                    except ET.ParseError as e:
                        print(f"Error parsing XML file {file_path}: {e}")
    
    def convert_to_graphviz(self):
        dot = graphviz.Digraph()
        G = nx.DiGraph()

        if self.attackGraph is None:
            print("Error: attackGraph is None. No data to process for input ", self.directory)
            return  # E

        try:
            vertices = self.attackGraph['attack_graph']['vertices']['vertex']
            
    
        except KeyError as e:
            print(f"Error extracting vertices: {e}")
            return

        for vertex in vertices:
            label = f'Index: {vertex["id"]}\nFact: {vertex["fact"]}\nType: {vertex["type"]}'
            dot.node(str(vertex["id"]), label=label)
            G.add_node(vertex['id'], id=vertex['id'], fact=vertex['fact'], type=vertex['type'], defense={})

        


        # Extract edges
        for arc in self.attackGraph['attack_graph']['arcs']['arc']:
            dot.edge(arc['src'], arc['dst'])
            G.add_edge(arc['dst'], arc['src'])

        self.attackTree = G

    def find_goal_and_attacker_nodes(self):
        print('we are in input ', self.directory)
        if self.attackTree is None:
            print('There is no attack tree for this input ', self.directory)
            return
        
        for node in self.attackTree.nodes:
            Node = self.attackTree.nodes[node]
            fact = self.attackTree.nodes[node].get('fact')

            out_edge = list(self.attackTree.out_edges(node))
            
            if fact is not None:
                splited_fact = fact.split('(')[0]
                if splited_fact == 'execCode' and not out_edge:
                    self.goalNodes.append(node)
                elif splited_fact == 'attackerLocated':
                    self.attackerNodes.append(Node)
    
    def get_cvss_scores(self, cve_id):
        """
        Fetches CVSS Exploitability, Impact scores, and Vector String from the NVD API for a given CVE ID.
        
        Args:
            cve_id (str): The CVE identifier (e.g., "CVE-2020-14231").
            
        Returns:
            dict: Dictionary with CVSS version, vector string, exploitability score, and impact score, or error message.
        """
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        api_key = os.getenv("NVD_API_KEY")
        headers = {'apiKey': api_key} if api_key else {}

        try:
            response = requests.get(api_url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            if data.get('vulnerabilities'):
                cve_item = data['vulnerabilities'][0]
                metrics = cve_item.get('cve', {}).get('metrics', {})

                if 'cvssMetricV31' in metrics:
                    score_data = metrics['cvssMetricV31'][0]
                    cvss_data = score_data['cvssData']
                    return {
                        "cvss_version": "3.1",
                        "vector_string": cvss_data.get('vectorString'),
                        "exploitability_score": score_data.get('exploitabilityScore'),
                        "impact_score": score_data.get('impactScore')
                    }
                elif 'cvssMetricV30' in metrics:
                    score_data = metrics['cvssMetricV30'][0]
                    cvss_data = score_data['cvssData']
                    return {
                        "cvss_version": "3.0",
                        "vector_string": cvss_data.get('vectorString'),
                        "exploitability_score": score_data.get('exploitabilityScore'),
                        "impact_score": score_data.get('impactScore')
                    }
                elif 'cvssMetricV2' in metrics:
                    score_data = metrics['cvssMetricV2'][0]
                    cvss_data = score_data['cvssData']
                    return {
                        "cvss_version": "2.0",
                        "vector_string": cvss_data.get('vectorString'),
                        "exploitability_score": score_data.get('exploitabilityScore'),
                        "impact_score": score_data.get('impactScore')
                    }
                else:
                    return {"error": "No CVSS scores available for this CVE."}
            else:
                return {"error": "CVE data is not available or no vulnerability metrics found."}

        except requests.RequestException as e:
            return {"error": f"Request failed: {e}"}
        except KeyError as e:
            return {"error": f"Key error: {e}"}

    
    def generate_incidents(self):
        if self.attackerNodes is None or self.attackTree is None:
            print('There are no incidents for input ', self.directory)
            return

        for starting_point in self.attackerNodes:
            starting_point_id = starting_point['id']

            rule_nodes = list(self.attackTree.out_edges(starting_point_id))


            queue = deque()
            visited = set()


            for _, second in rule_nodes:
                rule_node = self.attackTree.nodes[second].get('id')
                visited.add(rule_node)
                queue.append((rule_node, [rule_node]))


            while queue:
                node, path = queue.popleft()


                derived_nodes = list(self.attackTree.out_edges(node))
                if not derived_nodes:
                    continue

                derived_node = derived_nodes[0][1]


                if derived_node in self.goalNodes:
                    self.incidents.append(path)
                    self.averageIncidentLengh += len(path) + 1
                    continue

                next_rules = list(self.attackTree.out_edges(derived_node))

                for _, next_rule_node in next_rules:
                    if next_rule_node not in path:
                        node = next_rule_node
                        new_path = path.copy()
                        new_path.append(next_rule_node)
                        queue.append((node, new_path))

        print(len(self.incidents))
        self.averageIncidentLengh = self.averageIncidentLengh / len(self.incidents) if self.incidents else 0
    
    def find_cve_cvss_by_technique(self, mitre_technique):
        filtered = self.mitre_cve_df[self.mitre_cve_df['MITRE_Technique'] == mitre_technique]
        results = [
            (
                row['CVE'],
                float(row['CVSS']) if row['CVSS'] else None,
                row['cvss_vector'],
                float(row['exploitability_score']) if row['exploitability_score'] else None,
                float(row['impact_score']) if row['impact_score'] else None
            )
            for _, row in filtered.iterrows()
        ]
        return results

    def extract_information_related_to_goal_node(self, attack_goal_fact):
        sequence = {}
        attack_goal_fact = attack_goal_fact[:-1]
        attack_goal_fact = attack_goal_fact.split('(')[1]
        attack_goal_fact = attack_goal_fact.split(',')
        #print(attack_goal_fact)
        host = attack_goal_fact[0]
        sequence['host'] = host
        mitre_technique = attack_goal_fact[2]
        mitre_technique = mitre_technique[1:-1]
        sequence['mitre'] = mitre_technique
        results = self.find_cve_cvss_by_technique(mitre_technique)
        result = None
        cvss = None
        if results:
            result = random.choice(results)
            cve = result[0]
            cvss = result[1]
            cvss_vector = result[2]
            exploitability = result[3]
            impact = result[4]
            #cvss_results = self.get_cvss_scores(cve)
            sequence['exploitability'] = float(exploitability)
            sequence['impact'] = float(impact)
            sequence['cvss_vector'] = cvss_vector
            sequence['cve'] = cve
            sequence['cvss'] = cvss
        
        #print(sequence)
        return sequence, cvss 

    def convert_rules_to_goals(self):
        """
        The incidents(Attack paths) at first has been stored by the rules. 
        But it is better for them to be stored by goals.
        This function serves as converting rule-based incidents to goal-bases ones."""

        for incident in self.incidents:
            goal_based_incidents = {}
            sequences = []
            severities = []
            for attack_rule_node in incident:
                out_edges = list(self.attackTree.out_edges(attack_rule_node))
                if not out_edges:
                    continue
                attack_goal_node = out_edges[0][1]
                attack_goal_fact = self.attackTree.nodes[attack_goal_node].get('fact')
                if attack_goal_fact.split('(')[0] == 'execCode':
                    incident_sequence_item, cvss = self.extract_information_related_to_goal_node(attack_goal_fact)
                    if cvss is None:
                        continue
                    severities.append(cvss)
                    sequences.append(incident_sequence_item)
            
            
            #print(sequences)
            #print(severities)
            if sequences:
                self.goal_based_incidents.append(sequences)

    def calculate_entropy(self):
        """
        Calculate Shannon entropy for techniques, assets, and vulnerabilities.

        Returns:
            tuple of floats: (techniques_entropy, assets_entropy, vulns_entropy)
        """

        def entropy(flat_list):
            total = len(flat_list)
            if total == 0:
                return 0.0
            counts = Counter(flat_list)
            return -sum((count / total) * math.log2(count / total) for count in counts.values())

        all_techniques = [tech for subset in self.techniques_set for tech in subset]
        all_assets = [asset for subset in self.assets_set for asset in subset]
        all_vulns = [vuln for subset in self.vulns_set for vuln in subset]
        all_incidents = [incident for subset in self.incident_set for incident in subset]

        techniques_entropy = entropy(all_techniques)
        assets_entropy = entropy(all_assets)
        vulns_entropy = entropy(all_vulns)
        incident_entropy = entropy(all_incidents)

        return techniques_entropy, assets_entropy, vulns_entropy, incident_entropy


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

        techniques_jaccard = avg_jaccard(self.techniques_set)
        assets_jaccard = avg_jaccard(self.assets_set)
        vulns_jaccard = avg_jaccard(self.vulns_set)
        incident_jaccard = avg_jaccard(self.incident_set)

        return techniques_jaccard, assets_jaccard, vulns_jaccard, incident_jaccard

    def print_random_incidents(self):
        if not self.incidents or len(self.incidents) < 2:
            print("Not enough incidents to pick from.")
            return

        

        random_incidents = random.sample(self.incidents, 2)
        for incident in random_incidents:
            incident_sequence = []
            last_node = incident[-1]
            goal_node = list(self.attackTree.out_edges(last_node))[0][1]
            
            goal = self.attackTree.nodes[goal_node]
            
            for node in incident:
                fact_nodes = list(self.attackTree.in_edges(node))
                for _, fact_node in fact_nodes:
                    incident_sequence.append(self.attackTree.nodes[fact_node])
            incident_sequence.append(goal)
            #print(incident_sequence)



    def plot_diagrams(self, cvsss, unique_techniques_for_incidents, lengths,
        save_path1='cvss_plot.png', save_path2='value_distribution_scatter.png'):
        # Use seaborn style for aesthetics
        sns.set(style="whitegrid")

        # Check input lengths
        if not (len(cvsss) == len(unique_techniques_for_incidents) == len(lengths)):
            raise ValueError("All input lists must have the same length.")

        x = list(range(len(cvsss)))

        # --- First Diagram: CVSS Scores ---
        plt.figure(figsize=(12, 7))
        points = plt.scatter(x, cvsss, c=cvsss, cmap='coolwarm', s=80, edgecolors='k', alpha=0.8)
        plt.plot(x, cvsss, color='gray', linestyle='--', alpha=0.5)
        plt.colorbar(points, label='CVSS Score')
        plt.xlabel('Incident Index', fontsize=12)
        plt.ylabel('CVSS Score', fontsize=12)
        plt.title('CVSS Scores Over Incidents', fontsize=16, fontweight='bold')
        plt.ylim(0, 10)
        plt.xticks(fontsize=10)
        plt.yticks(fontsize=10)
        plt.tight_layout()
        plt.savefig(save_path1, dpi=300)
        plt.close()
        print(f"First plot (CVSS Scores) saved to {save_path1}")

        # --- Second Diagram: Value Count Scatter for Lengths and Unique T
        pair_counts = Counter(zip(lengths, unique_techniques_for_incidents))

        # Prepare data
        x_vals = [pair[0] for pair in pair_counts]         # incident lengths
        y_vals = [pair[1] for pair in pair_counts]         # number of unique techniques
        counts = list(pair_counts.values())                # how many incidents had each (x, y) pair
        sizes = [count * 40 for count in counts]           # scale point size for better visuals

        # Plot
        plt.figure(figsize=(12, 7))
        scatter = plt.scatter(
            x_vals,
            y_vals,
            s=sizes,
            c=counts,
            cmap='viridis',
            alpha=0.7,
            edgecolors='black',
            linewidth=0.5
        )

        # Annotate each point with its count
        for (x, y), count in pair_counts.items():
            plt.text(x, y + 0.25, str(count), ha='center', fontsize=9)

        # Style
        plt.xlabel('Incident Length', fontsize=14)
        plt.ylabel('Number of Unique Techniques', fontsize=14)
        plt.title('Frequency of (Length, Technique Count) Combinations', fontsize=16, fontweight='bold')
        plt.colorbar(scatter, label='Incident Count')
        plt.grid(True, linestyle='--', alpha=0.5)
        plt.xticks(fontsize=12)
        plt.yticks(fontsize=12)
        plt.tight_layout()
        plt.savefig(save_path2, dpi=300)
        plt.close()
        print(f"Second plot (Length vs Techniques Frequency) saved to {save_path2}")
    
    def calculate_scenario_statistics(self):
        lengths = []
        cvsss = []
        exploitabilities = []
        impacts = []
        risks = []
        curProb = 1
        curRisk = 0
        curImpact = 0
        unique_techniques_for_incidents = []
        incident_num = len(self.goal_based_incidents)
        diverse_techniques_for_all = []

        for incident in self.goal_based_incidents:
            if not incident:
                continue
            curProb = 1
            curRisk = 0
            curImpact = 0
            lengths.append(len(incident))
            #cvsss = []
            diverse_techniques = []
            cvss_sum = 0
            cves = []
            assets = []
            path = []
            
            for sequence in incident:
                #print(sequence)
                if not {'cve', 'exploitability', 'impact', 'cvss'}.issubset(sequence):
                    continue
                cve = sequence['cve']
                host = sequence['host']
                cves.append(cve)
                assets.append(host)
                path.append(host)
                path.append(cve)
                #cvss_metrics = self.get_cvss_scores(cve)
                newProb = sequence['exploitability'] / 10
                newImpact = sequence['impact']
                exploitabilities.append(sequence['exploitability'] / 10)
                impacts.append(sequence['impact'])
                curProb *= newProb
                curImpact += newImpact
                curRisk = curProb * curImpact
                risks.append(curRisk)
                cvss_sum += float(sequence['cvss'])
                diverse_techniques_for_all.append(sequence['mitre'])
                diverse_techniques.append(sequence['mitre'])
                path.append(sequence['mitre'])
            #print(diverse_techniques)
            self.incident_set.append(path)
            self.assets_set.append(assets)
            self.vulns_set.append(cves)
            self.techniques_set.append(diverse_techniques)
            unique_techniques = set(diverse_techniques)
            self.unique_techniques.append(len(unique_techniques))
            cvss_avg = cvss_sum / len(incident) if incident else 0
            cvsss.append(cvss_avg)

        #print(exploitabilities)
        #print(impacts)
        #print('Risks: ', risks)

        self.lengths = lengths
        self.cvsss = cvsss
        self.diverse_techniques_all = len(set(diverse_techniques_for_all))

        #print(self.techniques_set)
        #jac_tech, jac_ass, jac_vulns, jac_inc = self.calculate_jaccard()
        #ent_tech, ent_ass, ent_vulns, ent_inc = self.calculate_entropy()

        #print("Jaccurd: ", jac_tech, jac_ass, jac_vulns, jac_inc)
        #print("Entropy: ", ent_tech, ent_ass, ent_vulns, ent_inc)

        self.incidentsNum = len(lengths)
        self.avg_cvss = sum(cvsss) / len(cvsss) if cvsss else 0
        
        #self.plot_diagrams(cvsss, self.unique_techniques, lengths)
        return


# Example usage
if __name__ == "__main__":
    directories = [d for d in os.listdir(root_dir) if os.path.isdir(os.path.join(root_dir, d))]

    incidentGenerators = []

    incidentsNum = 0

    for dir in directories:
        #print(dir)
        if dir == 'NewTest':  # Check if the first character is uppercase
            #print(dir)
            start = time.time()
            incidentGenerator = IncidentGenerator(dir)
            incidentsNum += incidentGenerator.get_incidents_num()
            #incidentGenerator.print_random_incidents()
            #print(incidentGenerator.get_incidents_average_length())
            #print('Number: ', incidentGenerator.get_incidents_num())
            #print('Techniques: ', incidentGenerator.get_unique_techniques_num())
            #print('CVSS: ', incidentGenerator.get_avg_cvss())
            end = time.time()

            #print(f"Elapsed time: {end - start:.4f} seconds")

            #print(incidentsNum)
