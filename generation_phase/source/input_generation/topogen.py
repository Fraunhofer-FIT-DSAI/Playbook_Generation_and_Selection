import random
from topogen.mininet import MininetTopoGen

def generate_random_topology(num_switches=5, num_hosts=6, num_workstations=4, num_dmz=2, link_prob=0.5):
    topo = MininetTopoGen()
    nodes = {"switches": [], "hosts": [], "workstations": [], "dmz": [], "edges": []}

    # Add switches
    switches = [f"s{i}" for i in range(num_switches)]
    nodes["switches"].extend(switches)
    for switch in switches:
        topo.add_switch(switch)

    # Add regular hosts and connect to switches
    for i in range(num_hosts):
        host = f"h{i}"
        switch = random.choice(switches)  # Attach host to a random switch
        topo.add_host(host, switch=switch)
        nodes["hosts"].append(host)
        nodes["edges"].append((host, switch))

    # Add workstations and connect to switches
    for i in range(num_workstations):
        workstation = f"ws{i}"
        switch = random.choice(switches)
        topo.add_host(workstation, switch=switch)
        nodes["workstations"].append(workstation)
        nodes["edges"].append((workstation, switch))

    # Add DMZ servers and connect to switches
    for i in range(num_dmz):
        dmz_server = f"dmz{i}"
        switch = random.choice(switches)
        topo.add_host(dmz_server, switch=switch)
        nodes["dmz"].append(dmz_server)
        nodes["edges"].append((dmz_server, switch))

    # Add random links between switches
    for i in range(num_switches):
        for j in range(i + 1, num_switches):
            if random.random() < link_prob:  # Randomly decide if a link exists
                topo.add_link(switches[i], switches[j])
                nodes["edges"].append((switches[i], switches[j]))

    return nodes

def print_topology(topology):
    print("\n--- Random Network Topology ---")
    print("Switches:", topology["switches"])
    print("Hosts:", topology["hosts"])
    print("Workstations:", topology["workstations"])
    print("DMZ Servers:", topology["dmz"])
    print("Connections:")
    for edge in topology["edges"]:
        print(f"  {edge[0]} --- {edge[1]}")

# Generate and print the topology
topo = generate_random_topology(num_switches=4, num_hosts=5, num_workstations=3, num_dmz=2, link_prob=0.6)
print_topology(topo)
