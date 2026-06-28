# Artifact Manifest

This file summarizes the relevant public artifact contents.

## Phase Source Folders

- `generation_phase/source/AttackTree_generation/`: MulVAL execution helper.
- `generation_phase/source/Incident_generation/`: attack-graph-to-incident extraction and CVE/CVSS handling.
- `generation_phase/source/Response_generation/`: D3FEND-informed response generation logic.
- `generation_phase/source/input_generation/`: topology and MulVAL input generation helpers.
- `generation_phase/source/mulval-inputs/`: scenario-conditioned MulVAL cases used for the paper.
- `selection_phase/source/GraphDB/`: RDF/OWL files for D3FEND, community playbooks, and step mappings.
- `selection_phase/source/Playbook/`: community playbook input and ontology generation code.
- `selection_phase/source/Playbook-defend-mapping/`: semantic playbook-step to D3FEND mapping code and outputs.
- `selection_phase/source/Use-Case/`: ICS scenario CSVs, SPARQL queries, and baseline selection code.

Official MITRE ATT&CK STIX files and D3FEND OWL files are fetched on demand with `integration_phase/scripts/download_mitre_resources.py`; they are not committed by default.

## Canonical Integration Scripts

- `build_scenario_profiles.py`: creates shared scenario JSON profiles.
- `download_mitre_resources.py`: downloads official MITRE ATT&CK STIX and D3FEND resources needed for the full workflow.
- `generate_scenario_mulval_inputs.py`: creates scenario-conditioned MulVAL inputs.
- `export_generated_playbooks.py`: exports generated playbooks as normalized JSONL/CSV.
- `generated_playbooks_to_owl.py`: materializes generated playbooks as OWL/RDF.
- `reduce_generated_playbooks.py`: builds the reduced generated repository.
- `load_graphdb_files.py`: loads RDF files into GraphDB/RDF4J.
- `run_mcdm_selection.py`: runs community, generated, augmented, and reduced selection modes.
- `run_recall_evaluation.py`: computes direct, inferred, combined, achievable, and normalized recall.
- `run_selection_profile_comparison.py`: replays closed-loop-balanced, coverage-primary, and coverage-constrained selection.
- `run_portfolio_selection.py`: selects small playbook portfolios.
- `run_ablation_experiments.py`: produces the ablation summary and by-scenario table.
- `run_reduction_sensitivity.py`: evaluates generated-pool reduction sizes.
- `run_fairness_checks.py`: checks provenance leakage and source-scenario restrictions.
- `check_closed_loop_sanity.py`: checks core closed-loop invariants.
- `analyze_closed_loop_results.py`: produces diagnostics and candidate-loss summaries.
- `make_publication_tables.py`: generates CSV and LaTeX result tables.

## Bundled Generated Repository Files

- `results/generated_repository/reduced_generated_playbooks.owl`: reduced generated repository OWL used in the main experiment.
- `results/generated_repository/reduced_generated_playbooks_manifest.csv`: reduced generated repository manifest.
- `results/generated_repository/reduction_report.csv`: selected/rejected generated candidates by reduction.
- `results/generated_repository/reduction_summary.json`: aggregate reduction summary.

The full generated repository export is intentionally excluded from Git because it is large. Restore it from release/archive assets or regenerate it when running full reduction from scratch:

- `results/generated_repository/export/generated_playbooks.jsonl`
- `results/generated_repository/export/generated_playbook_steps.csv`
- `results/generated_repository/generated_playbooks.owl`
- `results/generated_repository/generated_playbooks_manifest.csv`

## Bundled Evaluation Outputs

- `results/evaluation/community-only/`: community baseline outputs.
- `results/evaluation/generated-reduced/`: generated-only reduced outputs.
- `results/evaluation/augmented-reduced/`: main closed-loop outputs.
- `results/evaluation/ablation_summary.csv`: ablation-level comparison.
- `results/evaluation/ablation_by_scenario.csv`: scenario-level ablation comparison.
- `results/evaluation/coverage_profile_summary.csv`: coverage-primary/constrained summary.
- `results/evaluation/coverage_profile_by_scenario.csv`: coverage profile scenario rows.
- `results/evaluation/portfolio_selection_summary.csv`: portfolio summary.
- `results/evaluation/portfolio_selection_by_scenario.csv`: portfolio scenario rows.
- `results/evaluation/reduction_sensitivity.csv`: retained-pool-size sensitivity.
- `results/evaluation/diagnostics/`: fairness, sanity, and closed-loop diagnostics.
- `results/evaluation/publication_tables/`: paper-ready CSV and LaTeX tables.
