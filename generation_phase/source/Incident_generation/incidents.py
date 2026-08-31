import os
import xml.etree.ElementTree as ET
import xmltodict
import random
from pathlib import Path
import networkx as nx
from collections import deque
from collections import Counter
import pandas as pd
import math






REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = Path(__file__).resolve().parents[1]
root_dir = os.getenv("MULVAL_INPUT_ROOT", str(SOURCE_ROOT / "mulval-inputs"))


class IncidentGenerator:
    def __init__(self, directory, max_incidents=None):
        self.directory = directory
        self.max_incidents = max_incidents
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
        cve_table_path = os.getenv(
            "CVE_MITRE_ENRICHED_PATH",
            str(REPO_ROOT / "data" / "scenario_profiles" / "CVE_MITRE_enriched.scenario.csv"),
        )
        self.mitre_cve_df = pd.read_csv(cve_table_path)
        seed_value = os.getenv("INCIDENT_SEED", "1337")
        try:
            seed = int(seed_value)
        except ValueError as exc:
            raise ValueError(f"INCIDENT_SEED must be an integer, got {seed_value!r}") from exc
        self._rng = random.Random(seed)
        self.techniques_set = []
        self.assets_set = []
        self.vulns_set = []
        self.incident_set = []

    
        self.read_attack_graph_file()
        self.convert_to_attack_tree()
        self.find_goal_and_attacker_nodes()
        self.generate_incidents()
        self.convert_rules_to_goals()
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
                    
                    try:
                        tree = ET.parse(file_path)
                        root = tree.getroot()
                        
                        tree_string = ET.tostring(root, encoding="unicode")
                        self.attackGraph = xmltodict.parse(tree_string)
                    
                    except ET.ParseError as e:
                        print(f"Error parsing XML file {file_path}: {e}")
    
    def convert_to_attack_tree(self):
        G = nx.DiGraph()

        if self.attackGraph is None:
            print("Error: attackGraph is None. No data to process for input ", self.directory)
            return

        try:
            vertices = self.attackGraph['attack_graph']['vertices']['vertex']
            
    
        except KeyError as e:
            print(f"Error extracting vertices: {e}")
            return

        for vertex in vertices:
            G.add_node(vertex['id'], id=vertex['id'], fact=vertex['fact'], type=vertex['type'], defense={})

        


        for arc in self.attackGraph['attack_graph']['arcs']['arc']:
            G.add_edge(arc['dst'], arc['src'])

        self.attackTree = G

    def find_goal_and_attacker_nodes(self):
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
                    if self.max_incidents and len(self.incidents) >= self.max_incidents:
                        self.averageIncidentLengh = self.averageIncidentLengh / len(self.incidents) if self.incidents else 0
                        return
                    continue

                next_rules = list(self.attackTree.out_edges(derived_node))

                for _, next_rule_node in next_rules:
                    if next_rule_node not in path:
                        node = next_rule_node
                        new_path = path.copy()
                        new_path.append(next_rule_node)
                        queue.append((node, new_path))

        self.averageIncidentLengh = self.averageIncidentLengh / len(self.incidents) if self.incidents else 0
    
    def find_cve_cvss_by_technique(self, mitre_technique):
        filtered = self.mitre_cve_df[self.mitre_cve_df['MITRE_Technique'] == mitre_technique]
        results = [
            (
                row['CVE'],
                float(row['CVSS']) if pd.notna(row['CVSS']) else None,
                row['cvss_vector'] if pd.notna(row['cvss_vector']) else None,
                float(row['exploitability_score']) if pd.notna(row['exploitability_score']) else None,
                float(row['impact_score']) if pd.notna(row['impact_score']) else None
            )
            for _, row in filtered.iterrows()
        ]
        return results

    def extract_information_related_to_goal_node(self, attack_goal_fact):
        sequence = {}
        attack_goal_fact = attack_goal_fact[:-1]
        attack_goal_fact = attack_goal_fact.split('(')[1]
        attack_goal_fact = attack_goal_fact.split(',')
        host = attack_goal_fact[0]
        sequence['host'] = host
        mitre_technique = attack_goal_fact[2]
        mitre_technique = mitre_technique[1:-1]
        sequence['mitre'] = mitre_technique
        results = self.find_cve_cvss_by_technique(mitre_technique)
        results = [r for r in results if None not in (r[1], r[2], r[3], r[4])]
        result = None
        cvss = None
        if results:
            result = self._rng.choice(results)
            cve = result[0]
            cvss = result[1]
            cvss_vector = result[2]
            exploitability = result[3]
            impact = result[4]
            sequence['exploitability'] = float(exploitability)
            sequence['impact'] = float(impact)
            sequence['cvss_vector'] = cvss_vector
            sequence['cve'] = cve
            sequence['cvss'] = cvss
        
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
            
            
            if sequences:
                self.goal_based_incidents.append(sequences)
                if self.max_incidents and len(self.goal_based_incidents) >= self.max_incidents:
                    return

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

    def calculate_scenario_statistics(self):
        lengths = []
        cvsss = []
        diverse_techniques_for_all = []

        for incident in self.goal_based_incidents:
            if not incident:
                continue
            lengths.append(len(incident))
            diverse_techniques = []
            cvss_sum = 0
            cves = []
            assets = []
            path = []
            
            for sequence in incident:
                if not {'cve', 'exploitability', 'impact', 'cvss'}.issubset(sequence):
                    continue
                cve = sequence['cve']
                host = sequence['host']
                cves.append(cve)
                assets.append(host)
                path.append(host)
                path.append(cve)
                cvss_sum += float(sequence['cvss'])
                diverse_techniques_for_all.append(sequence['mitre'])
                diverse_techniques.append(sequence['mitre'])
                path.append(sequence['mitre'])
            self.incident_set.append(path)
            self.assets_set.append(assets)
            self.vulns_set.append(cves)
            self.techniques_set.append(diverse_techniques)
            unique_techniques = set(diverse_techniques)
            self.unique_techniques.append(len(unique_techniques))
            cvss_avg = cvss_sum / len(incident) if incident else 0
            cvsss.append(cvss_avg)

        self.lengths = lengths
        self.cvsss = cvsss
        self.diverse_techniques_all = len(set(diverse_techniques_for_all))

        self.incidentsNum = len(lengths)
        self.avg_cvss = sum(cvsss) / len(cvsss) if cvsss else 0
