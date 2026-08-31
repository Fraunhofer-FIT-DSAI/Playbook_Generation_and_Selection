import pandas as pd
from pathlib import Path
import re
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, XSD

""" Generates playbook instances for the ontology in owl format, uses csv file for it"""

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def safe_fragment(value):
    text = "" if pd.isna(value) else str(value).strip()
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "unknown"


file_path = PROJECT_ROOT / "Playbook" / "steps-coded.csv"
df = pd.read_csv(file_path, sep=";")

vendors_to_include = ["FortiSOAR", "Rapid7", "XSOAR"]
df = df[df["vendor"].isin(vendors_to_include)]

IRSO = Namespace("http://www.semanticweb.org/user/ontologies/2025/1/IncidentResponseSecurityOntology#")
g = Graph()
g.bind("irso", IRSO)

for _, row in df.iterrows():
    playbook_uri = URIRef(IRSO + "Playbook_" + safe_fragment(row["playbook_id"]))
    step_uri = URIRef(IRSO + "Step_" + safe_fragment(row["step_id"]))
    vendor_uri = URIRef(IRSO + "Vendor_" + safe_fragment(row["vendor"]))
    actuator_uri = URIRef(IRSO + "Actuator_" + safe_fragment(row["actuator"]))
    action_uri = URIRef(IRSO + "Action_" + safe_fragment(row["action"]))
    artifact_uri = URIRef(IRSO + "Artifact_" + safe_fragment(row["artifact"]))
    step_type_uri = URIRef(IRSO + "StepType_" + safe_fragment(row["step_types"]))
    automation_uri = URIRef(IRSO + "AutomationLevel_" + safe_fragment(row["automation"]))

    g.add((playbook_uri, RDF.type, IRSO.Playbook))
    g.add((playbook_uri, IRSO.hasPlaybookID, Literal(str(row["playbook_id"]), datatype=XSD.string)))
    g.add((playbook_uri, IRSO.hasPlaybookName, Literal(str(row["playbook_name"]), datatype=XSD.string)))
    g.add((playbook_uri, IRSO.hasPlaybookDescription, Literal(str(row["playbook_description"]), datatype=XSD.string)))

    g.add((vendor_uri, RDF.type, IRSO.Vendor))
    g.add((playbook_uri, IRSO.providedBy, vendor_uri)) 

    g.add((step_uri, RDF.type, IRSO.Step))
    g.add((step_uri, IRSO.hasStepID, Literal(str(row["step_id"]), datatype=XSD.string)))
    g.add((step_uri, IRSO.hasStepName, Literal(str(row["step_names"]), datatype=XSD.string)))
    g.add((step_uri, IRSO.hasStepDescription, Literal(str(row["step_description"]), datatype=XSD.string)))

    g.add((playbook_uri, IRSO.hasStep, step_uri))

    g.add((actuator_uri, RDF.type, IRSO.Actuator))
    g.add((step_uri, IRSO.performedBy, actuator_uri))

    g.add((action_uri, RDF.type, IRSO.Action))
    g.add((step_uri, IRSO.hasAction, action_uri))

    g.add((artifact_uri, RDF.type, IRSO.Artifact))
    g.add((step_uri, IRSO.affects, artifact_uri))

    g.add((step_type_uri, RDF.type, IRSO.StepType))
    g.add((step_uri, IRSO.hasStepType, step_type_uri))

    g.add((automation_uri, RDF.type, IRSO.AutomationLevel))
    g.add((step_uri, IRSO.hasAutomationLevel, automation_uri))

output_file = PROJECT_ROOT / "GraphDB" / "playbooks.owl"
g.serialize(destination=output_file, format="xml")
