import xml.etree.ElementTree as ET
import csv

""" Parse the scada dependency model from xml to python dictionary and to csv format """

def clean_component_name(description):
    """
    Extracts a component name by removing everything after 'is' or 'are'.
    Also, removes all spaces.
    """
    if not description:
        return None
    
    # Normalize case to handle "is" and "are" correctly
    description = description.strip()
    lower_desc = description.lower()
    
    # Find the cutoff point
    cutoff = min(
        [lower_desc.find(keyword) for keyword in [" is ", " are "] if lower_desc.find(keyword) != -1],
        default=len(description)
    )

    cleaned_name = description[:cutoff]  # Remove text after 'is' or 'are'
    return cleaned_name.replace(" ", "")  # Remove all spaces


def parse_dependency_model(xml_file):
    """Parses the SCADA dependency model XML file and returns a structured dictionary with unique IDs."""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    dependency_model = {}
    component_id = 1  # Start component IDs from 1

    def extract_dependencies(node):
        """Recursive function to traverse dependency tree and extract relationships."""
        nonlocal component_id

        component_description = node.get("description").replace(",", "") # to have a consistent naming 
        dep_type = node.get("Type")  # Default to AND if not specified

        if not component_description:
            return  # Skip nodes with no description

        # Normalize names
        component_name = clean_component_name(component_description)

        dependencies = []
        for child in node.findall("paragon"):
            child_desc = child.get("description")
            if child_desc:
                dep_name = clean_component_name(child_desc).replace(",", "")
                dependencies.append(dep_name)

        key = f"{component_name}_{component_id}"
        # Assign ID and store data
        dependency_model[key] = {
            "id": component_id,
            "name": component_name,
            "description": component_description,
            "dependencies": dependencies,  # Store as a comma-separated string
            "type": dep_type,
            "status": 1  # Initially assume all components are operational
        }
        component_id += 1  #

        # Recursive extraction for child nodes
        for child in node.findall("paragon"):
            extract_dependencies(child)

    extract_dependencies(root)
    return dependency_model

# save the file in csv format
def save_to_csv(dependency_model, csv_file_path):
    """Saves the dependency model dictionary to a CSV file."""
    with open(csv_file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file) 
        writer.writerow(["Component ID", "Component Name", "Component Description", "Dependencies", "Type", "Status"])
        for component_desc, data in dependency_model.items():
            writer.writerow([data["id"], data["name"], data["description"], data["dependencies"], data["type"], data["status"]])

# Load SCADA Dependency Model
xml_file_path = "Use-Case/SCADA.dependencymodel.xml"
dependency_model = parse_dependency_model(xml_file_path)

# Save to CSV
csv_file_path = "Use-Case/MainPart/dependency_model.csv"
save_to_csv(dependency_model, csv_file_path)

# Print first 5 extracted dependencies
#print("\nFirst 5 Entries in Parsed Dependency Model:")
#for key in list(dependency_model.keys())[:5]:
    #print(f"  ID: {dependency_model[key]['id']}, Name: {dependency_model[key]['name']}, Description: {key}, Dependencies: {dependency_model[key]['dependencies']}")

#print(f"\nDependency model saved to {csv_file_path}")
