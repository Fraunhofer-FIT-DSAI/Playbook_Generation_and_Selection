# Playbook_Generation_and_Selection

This repository contains the code, inputs, generated repository files, diagnostics, and result tables for the paper:

**Semantic and Provenance-Aware Selection of Incident Response Playbooks through Attack-Graph-Based Repository Enrichment**
Submitted to SecAI 2026 (ESORICS workshop)

The artifact is organized by method phases. It supports:

- attack-graph-conditioned playbook generation;
- ontology-backed community playbook selection;
- strict-provenance closed-loop integration of generated and community playbooks;
- generated-repository reduction;
- fairness/leakage checks, ablations, coverage-aware selection, portfolio selection, and publication tables.

## Repository Layout

```text
generation_phase/
  source/                         Attack-graph, incident, response-generation, and MulVAL helper code.

selection_phase/
  source/                         Community playbook ontology, D3FEND mappings, scenario queries, and baseline selector inputs.

integration_phase/
  scripts/                        Canonical scripts used for the closed-loop paper evaluation.

data/
  scenario_profiles/              Shared ATT&CK/CVE scenario profiles used by both phases.

results/
  generated_repository/           Exported generated playbooks, generated OWL, reduced OWL, manifests, and reduction report.
  evaluation/                     Selection outputs, diagnostics, ablations, portfolio results, and publication tables.

docs/
  artifact_manifest.md            File-level overview of the public artifact.
```

## Setup

Python 3.9+ is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Optional dependencies are only needed for legacy preprocessing or full regeneration of semantic mappings:

```bash
pip install -r requirements-optional.txt
```

External services/tools:

- **GraphDB or another RDF4J-compatible triplestore** is required to rerun SPARQL-backed selection.
- **MulVAL** is required only if regenerating attack graphs from `input.P`; precomputed MulVAL outputs are bundled for the paper scenarios.
- **Docker** can be used by `generation_phase/source/AttackTree_generation/mulval_pipeline.py` if a local MulVAL command is not available.


## External Resources

Official MITRE ATT&CK STIX snapshots and the MITRE D3FEND ontology are not committed to Git by default. Fetch them before running the full workflow:

```bash
python integration_phase/scripts/download_mitre_resources.py
```

The downloader uses the MITRE CTI tag `ATT&CK-v19.1` by default and writes a local manifest to `data/external_resource_manifest.json`. Downloaded MITRE files are ignored by Git. 

Large full generated-repository files are attached as release/archive assets.


## Fast Reproduction From Bundled Outputs

The bundled files under `results/` reproduce the paper results without rerunning MulVAL or GraphDB.
It regenerates publication tables from the bundled result CSV/JSON files.

```bash
python integration_phase/scripts/make_publication_tables.py
```

Outputs:

```text
results/evaluation/publication_tables/table_a_main_closed_loop_comparison.csv
results/evaluation/publication_tables/table_a_main_closed_loop_comparison.tex
results/evaluation/publication_tables/table_b_direct_vs_inferred.csv
results/evaluation/publication_tables/table_b_direct_vs_inferred.tex
results/evaluation/publication_tables/table_c_weakest_normalized_recall.csv
results/evaluation/publication_tables/table_c_weakest_normalized_recall.tex
```

Run consistency checks over the bundled result files:

```bash
python integration_phase/scripts/check_closed_loop_sanity.py
python integration_phase/scripts/run_fairness_checks.py
python integration_phase/scripts/analyze_closed_loop_results.py
```

Key diagnostic outputs:

```text
results/evaluation/diagnostics/sanity_summary.json
results/evaluation/diagnostics/fairness_checks.json
results/evaluation/diagnostics/closed_loop_diagnostics_summary.json
```

## Full Reproduction Workflow

The following steps rebuild the closed-loop artifacts from phase inputs. Steps requiring external software are marked.

### 1. Build Shared Scenario Profiles

```bash
python integration_phase/scripts/build_scenario_profiles.py
```

Outputs:

```text
data/scenario_profiles/*.json
data/scenario_profiles/index.json
```

The profiles contain ATT&CK mappings and available `top_cve` evidence. They do not contain complete host, asset, or artifact annotations; artifacts are inferred later through ATT&CK-D3FEND relations.

### 2. Generate Scenario-Conditioned MulVAL Inputs

```bash
python integration_phase/scripts/generate_scenario_mulval_inputs.py
```

Outputs:

```text
generation_phase/source/mulval-inputs/scenario_*/input.P
generation_phase/source/mulval-inputs/scenario_*/rules.P
data/scenario_profiles/CVE_MITRE_enriched.scenario.csv
```

### 3. Regenerate Attack Graphs With MulVAL

This step is optional for checking the published results because precomputed attack-graph outputs are bundled.

Using Docker:

```bash
cd generation_phase/source
./AttackTree_generation/mulval_pipeline.py "$PWD/mulval-inputs" --runner docker
cd ../..
```

Using an existing shell function named `mulval_exec`:

```bash
cd generation_phase/source
./AttackTree_generation/mulval_pipeline.py "$PWD/mulval-inputs" --runner function
cd ../..
```

### 4. Export Generated Playbooks

```bash
python integration_phase/scripts/export_generated_playbooks.py \
  --all-cases \
  --limit 500 \
  --cve-table data/scenario_profiles/CVE_MITRE_enriched.scenario.csv
```

Outputs:

```text
results/generated_repository/export/generated_playbooks.jsonl
results/generated_repository/export/generated_playbook_steps.csv
results/generated_repository/export/summary.json
```

The JSONL file is the compact normalized representation of the generated playbooks. Individual CACAO-shaped JSON files are intentionally not bundled because they duplicate the JSONL/OWL artifacts.

### 5. Convert Generated Playbooks To OWL

```bash
python integration_phase/scripts/generated_playbooks_to_owl.py
```

Outputs:

```text
results/generated_repository/generated_playbooks.owl
results/generated_repository/generated_playbooks_manifest.csv
```

The OWL materializes:

- playbook-level and step-level direct ATT&CK provenance;
- D3FEND defensive technique links;
- CVE, host, artifact, risk, action-count, phase, scenario, and attack-path metadata where available.

### 6. Reduce Generated Repository

```bash
python integration_phase/scripts/reduce_generated_playbooks.py \
  --strategy hybrid \
  --per-scenario 50
```

Outputs:

```text
results/generated_repository/reduced_generated_playbooks.owl
results/generated_repository/reduced_generated_playbooks_manifest.csv
results/generated_repository/reduction_report.csv
results/generated_repository/reduction_summary.json
```

The paper uses the `hybrid` strategy with `--per-scenario 50`. 

### 7. Load GraphDB

Create a GraphDB repository named `incident-response`, then load the base ontology, D3FEND, community playbooks, semantic playbook-D3FEND mappings, and generated playbooks.

For the main augmented-reduced experiment:

```bash
python integration_phase/scripts/load_graphdb_files.py --clear \
  selection_phase/source/IncidentResponseSecurityOntology.rdf \
  selection_phase/source/GraphDB/d3fend.owl \
  selection_phase/source/GraphDB/playbooks.owl \
  selection_phase/source/GraphDB/playbook_step_defend_mapping.owl \
  results/generated_repository/reduced_generated_playbooks.owl
```

For the augmented-all ablation, replace `reduced_generated_playbooks.owl` with `generated_playbooks.owl`.

### 8. Run Selection Modes

Community baseline:

```bash
python integration_phase/scripts/run_mcdm_selection.py \
  --mode community-only \
  --scoring-profile coverage-only \
  --out-dir results/evaluation/community-only
```

Main closed-loop top-1 experiment:

```bash
python integration_phase/scripts/run_mcdm_selection.py \
  --mode augmented-reduced \
  --scoring-profile closed-loop-balanced \
  --out-dir results/evaluation/augmented-reduced
```

Generated-only reduced experiment:

```bash
python integration_phase/scripts/run_mcdm_selection.py \
  --mode generated-reduced \
  --scoring-profile closed-loop-balanced \
  --out-dir results/evaluation/generated-reduced
```

Generated playbooks are restricted to their matching source scenario/case by default. The flag `--allow-cross-scenario-generated` is only for ablation.

### 9. Run Evaluation Variants

```bash
python integration_phase/scripts/run_selection_profile_comparison.py
python integration_phase/scripts/run_portfolio_selection.py
python integration_phase/scripts/run_ablation_experiments.py
python integration_phase/scripts/run_reduction_sensitivity.py
python integration_phase/scripts/run_fairness_checks.py
python integration_phase/scripts/check_closed_loop_sanity.py
python integration_phase/scripts/analyze_closed_loop_results.py
python integration_phase/scripts/make_publication_tables.py
```

## Result Interpretation

- `combined_attack_recall` is the union of direct ATT&CK provenance and inferred ATT&CK coverage through the ATT&CK-artifact-D3FEND path.
- `achievable_combined_attack_recall` is the coverage reachable by the candidate pool for a scenario.
- `normalized_combined_attack_recall` is selected coverage divided by achievable coverage.
- Portfolio recall evaluates whether a small set of playbooks can cover more of the reachable scenario coverage than one top-ranked playbook.
