import argparse
import os
import random
import shutil

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd

from mulval_convertor import *


class Topology:
    def __init__(self, directory, node_num=10, probability=0.1, seed=None):
        """
        Initializes the class with an empty NetworkX graph.
        Each node can have attributes:
        - 'role' (e.g., user, admin, etc.)
        - 'service' (e.g., web server, database, etc.)
        - 'vulnerabilities' (e.g., list of vulnerability IDs or descriptions)
        """
        self.directory = directory
        self.node_num = node_num
        self.probability = probability
        self.seed = seed
        
        # Create the random graph
        while True:
            G = nx.erdos_renyi_graph(self.node_num, probability, seed=seed)

            if nx.is_connected(G):
                self.graph = G
                self.density = nx.density(G)
                print('Density: ', self.density)
                break

    def get_density(self):
        print(self.density)

    def assign_roles(self):
            internet_node = random.choice(list(self.graph.nodes))
            self.graph.nodes[internet_node]['role'] = 'internet'

            self.distinct_roles = set([])

            cnt = 1

            for node in self.graph.nodes:
                if node != internet_node:
                    self.graph.nodes[node]['role'] = 'host' + str(cnt)
                    cnt += 1
                    #self.graph.nodes[node]['role'] = 'webServer'
                    #if self.graph.nodes[node]['role'] != 'internet':
                    #    self.distinct_roles.add(self.graph.nodes[node]['role'])



    def assign_vulnerabilities(self):
        """
        """
        cve_mitre_df = pd.read_csv('input_generation/CVE_MITRE.csv')
        cve_mitre_records = list(cve_mitre_df.itertuples(index=False, name=None))  # (CVE, MITRE_Technique)

        for node in self.graph.nodes:
            if self.graph.nodes[node]['role'] != 'internet':
                s = []
                # Randomly select vulnerability records for this host.
                selected_records = random.sample(cve_mitre_records, 2)
                for record in selected_records:
                    s.append(list(record))  # Convert tuple (CVE, MITRE_Technique) into a list [CVE, MITRE_Technique]
                self.graph.nodes[node]['vulns'] = s

                #print(self.graph.nodes[node]['vulns'])
    

    def list_roles(self):
        """
        Returns a list of all roles present in the graph.
        :return: List of roles.
        """
        topol_roles = []
        for node in self.graph.nodes:
            topol_roles.append(self.graph.nodes[node]['role'])
        return topol_roles
    
    def list_services(self):
        """
        Returns a list of all services present in the graph.
        :return: List of services.
        """

        
        for node in self.graph.nodes:
            print(self.graph.nodes[node]['services'])



        #return list({self.graph.nodes[node]['service'] for node in self.graph.nodes if 'service' in self.graph.nodes[node]})

    def list_vulnerabilities(self):
        """
        Returns a list of all vulnerabilities present in the graph.
        :return: List of vulnerabilities.
        """
        for node in self.graph.nodes:
            print(self.graph.nodes[node]['vulns'])

        return
    

    def visualize(self):
        # Visualize and save the graph as an image
        plt.figure(figsize=(8, 6))  # Set the figure size

        pos = nx.spring_layout(self.graph)  # You can change the layout if needed


        nx.draw_networkx_nodes(self.graph, pos, node_color='lightblue', node_size=500)


        # Draw the edges
        nx.draw_networkx_edges(self.graph, pos)

        # Create a dictionary of node labels based on the role attribute
        role_labels = {node: self.graph.nodes[node]['role'] for node in self.graph.nodes()}

        # Draw the labels (roles) on the nodes
        nx.draw_networkx_labels(self.graph, pos, labels=role_labels, font_size=10)

        plt.title(f'Random Network with {self.node_num} Nodes')

        
        # Save the visualization as a PNG file in the directory
        save_path = os.path.join(self.directory, 'network.png')
        print(f"Saving network visualization to: {save_path}")  # Debugging: print save path
        plt.savefig(save_path)
        plt.close()  # Close the figure to avoid display


    def write_to_mulval(self):
         # Define the file path
        file_path = os.path.join(self.directory, 'input.P')

    

        # Open the file for writing
        try:
            with open(file_path, 'w') as file:

                #   Writing the connections(hacl)
                file.write('/* Connections */\n')
                for node1, node2 in self.graph.edges():
                    # Call the hacl function with node1, node2, and two underscores as placeholders
                    file.write(hacl(self.graph.nodes[node1]['role'], self.graph.nodes[node2]['role'], '_', '_'))
                    file.write(hacl(self.graph.nodes[node2]['role'], self.graph.nodes[node1]['role'], '_', '_'))

                
                file.write('\n')
                #file.write('/* Running services */\n')
                #for node in self.graph.nodes():
                #    role = self.graph.nodes[node]['role']
                #    if role != 'internet':
                #        services = self.graph.nodes[node]['services']
        
                #        for service in services:
                #            file.write(progRunning(service, role))

                #file.write('\n')
                file.write('/* Vulnerabilities */\n')

                for node in self.graph.nodes():
                    role = self.graph.nodes[node]['role']
                    if role != 'internet':
                        #services = self.graph.nodes[node]['services']
                        vulns1 = self.graph.nodes[node]['vulns']
                        for vuln in vulns1:
                            cve_id = vuln[0]
                            mitre_id = vuln[1]
                        #for service, vulnerability in zip(services, vulns1):
                            file.write(vulExists(role, cve_id, mitre_id))  
                        #    file.write(vulProperty(vulnerability, 'remoteExploit', 'privEscalation'))
                
                file.write('\n')
                file.write('\n')

                file.write('/* Attacker Goals */\n')

                ## Setting attacker Goals
                file.write(attackerLocated('internet'))
                num_nodes = self.graph.number_of_nodes()
                random_number = random.randint(1, num_nodes - 1)
                random_role = 'host' + str(random_number)
                print(attackGoal(random_role))
                file.write(attackGoal(random_role))
                
                ## Setting the rules
                #file.write(execGoalRule())
            
            # Debugging message to confirm successful writing
            print(f"File 'input.P' successfully created and written at: {file_path}")
    
        except Exception as e:
            raise RuntimeError(f"An error occurred while writing to {file_path}: {e}") from e


def create_directories_and_files(dataset_size, parent_dir='mulval-inputs'):
    # Define the parent directory
    # Create the parent directory if it doesn't exist
    os.makedirs(parent_dir, exist_ok=True)
    directories = []

    for entry in os.listdir(parent_dir):
        full_dir_path = os.path.join(parent_dir, entry)
        if os.path.isdir(full_dir_path):
            shutil.copy('mulval-new-rules.P', os.path.join(full_dir_path, 'rules.P'))
    
    # Loop to create n directories and the file inside each
    for i in range(dataset_size):
        # Define the directory name
        dir_name = f'input{i}'
        
        # Create the full path for the new directory
        full_dir_path = os.path.join(parent_dir, dir_name)
        
        # Create the directory
        os.makedirs(full_dir_path, exist_ok=True)
        
        # Define the file name
        file_name = 'input.P'
        
        # Create the full path for the file
        full_file_path = os.path.join(full_dir_path, file_name)

        directories.append(full_dir_path)

        shutil.copy("mulval-new-rules.P", os.path.join(full_dir_path, 'rules.P'))

    return directories


def parse_args():
    parser = argparse.ArgumentParser(description="Generate reproducible MulVAL topology inputs.")
    parser.add_argument("--dataset-size", type=int, default=10)
    parser.add_argument("--node-num", type=int, default=10)
    parser.add_argument("--edge-probability", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--input-dir", default="mulval-inputs")
    return parser.parse_args()


def main():
    args = parse_args()
    random.seed(args.seed)
    directories = create_directories_and_files(args.dataset_size, args.input_dir)

    topologies = []
    for i in range(args.dataset_size):
        topol = Topology(
            directories[i],
            node_num=args.node_num,
            probability=args.edge_probability,
            seed=args.seed + i,
        )
        topol.assign_roles()
        topol.list_roles()
        topol.assign_vulnerabilities()
        topol.visualize()
        topol.write_to_mulval()
        topologies.append(topol)


if __name__ == "__main__":
    main()
