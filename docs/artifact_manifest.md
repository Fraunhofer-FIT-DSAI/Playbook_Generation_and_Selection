# Artifact Manifest

## Code

### Generation

- `generation_phase/source/AttackTree_generation/mulval_pipeline.py`:
  optional MulVAL execution over scenario inputs.
- `generation_phase/source/Incident_generation/incidents.py`: attack-path
  extraction and deterministic incident construction.
- `generation_phase/source/Response_generation/extractDefenseKnowledge.py`:
  countermeasure retrieval, CVSS v3.1 adjustment, and contextual residual-risk
  assignment.
- `integration_phase/scripts/export_generated_playbooks.py`: normalized
  playbook and step export for configurable `K`.
- `integration_phase/scripts/generated_playbooks_to_owl.py`: generated
  playbook OWL and manifest materialization.
- `integration_phase/scripts/reduce_generated_playbooks.py`: deterministic
  per-scenario semantic, Pareto, and relative-risk reduction.
- `integration_phase/scripts/summarize_generation_k_sweep.py`: `K=0..10`
  summary and recommendation rule.
- `integration_phase/scripts/analyze_generation_diversity.py`: exact pairwise
  Jaccard and occurrence-level Shannon entropy for the unreduced and retained
  `K=3` corpora.

### Selection

- `integration_phase/scripts/closed_loop_common.py`: GraphDB queries,
  provenance filtering, source restriction, and shared coverage helpers.
- `integration_phase/scripts/selection_protocol.py`: criteria, weights,
  missing-value rules, recall definitions, and tie policy.
- `integration_phase/scripts/run_mcdm_selection.py`: GraphDB-backed retrieval,
  criteria calculation, ranking, and recall.
- `integration_phase/scripts/compare_modes.py`: mode comparison.
- `integration_phase/scripts/run_selection_profile_comparison.py`:
  coverage-primary and coverage-constrained top-1.
- `integration_phase/scripts/run_portfolio_selection.py`: deterministic greedy
  portfolio selection.
- `integration_phase/scripts/run_ablation_experiments.py`: missing-policy and
  criterion ablations.
- `selection_phase/source/Playbook-defend-mapping/MainPart/playbook-defend-mapping.py`:
  optional pinned SBERT rerun that writes separately from the submitted mapping.

### Verification and Robustness

- `tests/test_generation_correctness.py`: exhaustive CVSS v3.1 subscore checks
  and real-incident `K=0..10` risk/provenance invariants.
- `audit_semantic_mapping.py` and `diagnose_sbert_mapping.py`: mapping
  integrity and descriptive confidence diagnostics.
- `verify_graphdb_load.py`: GraphDB counts, manifest identity, and hashes.
- `check_closed_loop_sanity.py`: coverage, source, tie, and bounds invariants.
- `check_selection_determinism.py`: canonical comparison of repeated runs.
- `run_fairness_checks.py`: source-scenario and provenance checks.
- `analyze_significance.py`: paired bootstrap, permutation, Wilcoxon, and
  effect-size analysis.
- `run_weight_sensitivity.py`: one-at-a-time perturbations and 5,000 seeded
  Dirichlet draws.
- `run_corrected_reduction_sensitivity.py`: full GraphDB-backed cap
  sensitivity.
- `build_coverage_reduction_alternatives.py` and
  `analyze_source_reduction_experiments.py`: coverage-aware reducer
  ablations.
- `analyze_generated_source_selection.py`: generated/community winner
  diagnostics.
- `make_weak_profile_figure.py`: tie-preserving weak-profile extraction and
  compact TikZ figure generation from the recorded augmented K=3 results.
- `make_corrected_publication_outputs.py`: paper-ready CSV, LaTeX, and figure
  outputs.

## Inputs

- `data/scenario_profiles/`: 16 canonical profiles and the
  scenario-conditioned CVE table.
- `generation_phase/source/mulval-inputs/`: fixed attack-graph cases.
- `generation_phase/source/defense_techniques/`: ATT&CK-artifact-D3FEND
  mapping tables.
- `selection_phase/source/IncidentResponseSecurityOntology.rdf`: base
  ontology.
- `selection_phase/source/GraphDB/d3fend.owl`: D3FEND ontology used in the
  evaluated GraphDB state.
- `selection_phase/source/GraphDB/playbooks.owl`: 469-playbook community
  repository.
- `selection_phase/source/GraphDB/playbook_step_defend_mapping.owl`: 4,016
  submitted top-1 step associations.
- `selection_phase/source/Use-Case/`: scenario target CSVs and SPARQL queries.

## Generated Repository Results

- `results/generated_repository/corrected_k03/`: 167-playbook OWL,
  manifest, full reduction report, and summary.
- `results/generated_repository/k_sweep/k_sensitivity_summary.csv`: all
  `K=0..10` metrics and deltas.
- `results/generated_repository/k_sweep/k_sensitivity_summary.json`: inputs,
  hashes, invariants, and recommendation.

## Evaluation Results

- `community-only/`, `generated-reduced/`, and `augmented-reduced/`:
  candidate tables, coverage maps, selected rows, and selection metadata.
- `closed_loop_comparison.csv`: scenario and aggregate mode comparison.
- `selection_profiles/`: predefined top-1 coverage profiles.
- `portfolio/`: greedy `K<=3` portfolios.
- `ablations/`: missing-policy and criterion ablations.
- `weight_sensitivity/`: one-at-a-time and 5,000-draw robustness.
- `significance_tests.csv` and `.json`: paired uncertainty analysis.
- `fairness_checks.*`, `sanity_*.*`, and `determinism_check.json`:
  integrity results.
- `sbert_mapping_diagnostics.csv` and
  `sbert_mapping_cutoff_diagnostics.csv`: descriptive mapping diagnostics.
- `source_selection_diagnostics.csv`, `source_weight_stability.csv`, and
  `source_counts_by_profile.csv`: selected-source analysis.
- `reduction_effect_by_scenario.csv` and
  `reduction_alternative_*.csv`: full-pool and alternative-reducer summaries.
- `publication_tables/` and `publication_figures/`: regenerated paper-ready
  outputs.
- `corrected_weak_normalized_profiles.csv` and `.tex`: the six profiles at or
  below the fifth-order normalized-recall cutoff; six are shown because three
  profiles tie at the cutoff.
- `generation_diversity_diagnostics.csv` and `.json`: definitions, input
  hashes, full-corpus values, and retained-repository values for the generation
  diversity diagnostic.

## Benchmark Records

- `results/ics_scenario_inventory.csv`, `ics_scenario_jaccard.csv`, and
  `ics_scenario_summary.json`: benchmark inventory and overlap.
- `results/evaluation/corrected/community_corpus_summary.csv`: observed source
  corpus and vendor-filter counts.
- `data/community_corpus_acquisition.json` and
  `data/ics_scenario_corpus_acquisition.json`: recorded corpus provenance and
  explicit limits of the available source snapshot.

## Separate Release

The full unreduced K=3 repository and large alternative repositories are listed
in `docs/release_artifacts.md`. They are excluded from Git and distributed as
the `v0.2` release asset.
