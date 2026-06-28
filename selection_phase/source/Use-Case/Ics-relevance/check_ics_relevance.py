import pandas as pd
import re
import xml.etree.ElementTree as ET

"""
Identifies ICS-relevant playbooks by extracting keywords from a SCADA
dependency model and checking if those keywords appear in playbook steps.
"""

# Load the playbook CSV
playbook_file = 'Playbook-defend-mapping/Preprocessing/filtered_playbooks.csv'
df = pd.read_csv(playbook_file, delimiter=',', skipinitialspace=True)
# Load and parse the SCADA dependency model XML
xml_file = 'Use-Case/SCADA.dependencymodel.xml'
with open(xml_file, 'r', encoding='utf-8') as file:
    scada_xml_content = file.read()

root = ET.fromstring(scada_xml_content)
descriptions = [elem.attrib['description'] for elem in root.iter() if 'description' in elem.attrib]

# Function to extract keywords from descriptions
def extract_keywords_from_description(description):
    cleaned = re.sub(r'[^a-zA-Z0-9\s]', '', description)
    words = cleaned.lower().split()
    stopwords = {'is', 'the', 'of', 'a', 'an', 'and', 'to', 'are', 'ok', 'set', 'be', 'for', 'on', 'in', 'or'}
    return [word for word in words if len(word) > 2 and word not in stopwords]

# Generate a unique set of keywords
scada_keywords = set()
for desc in descriptions:
    scada_keywords.update(extract_keywords_from_description(desc))

# Function to detect if any SCADA keyword is present in a text
def contains_broadened_ics_keyword(text):
    if pd.isnull(text):
        return False
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in scada_keywords)

# Apply detection across step description, action, and artifact columns
df['ics_relevant'] = df.apply(
    lambda row: contains_broadened_ics_keyword(str(row['step_description'])) or
                contains_broadened_ics_keyword(str(row['action'])) or
                contains_broadened_ics_keyword(str(row['artifact'])), axis=1)

# Calculate stats
total_playbooks = df['playbook_id'].nunique()
ics_playbooks = df[df['ics_relevant']]['playbook_id'].nunique()
ics_percentage = (ics_playbooks / total_playbooks) * 100

print(f"Total playbooks: {total_playbooks}")
print(f"ICS-relevant playbooks: {ics_playbooks}")
print(f"Percentage ICS-relevant: {ics_percentage:.2f}%")

# Optional: show example ICS-relevant steps
ics_examples = df[df['ics_relevant']][['playbook_name', 'step_description', 'action', 'artifact']].head(5)
print("\nExample ICS-relevant steps:\n", ics_examples)
