# Reproducing the Paper Results

Run commands from the repository root. The checked-in result set uses Python
3.14.5, `INCIDENT_SEED=1337`, and GraphDB 10.3.1 with a repository named
`incident-response`.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-lock.txt
```

`requirements.txt` lists the direct dependencies without version pins.
`requirements-optional.txt` is needed only to create a new SBERT mapping; the
paper evaluation uses the submitted mapping included in the repository.

## Verify the Included Artifacts

```bash
python integration_phase/scripts/build_ics_scenario_inventory.py
python integration_phase/scripts/audit_semantic_mapping.py
python integration_phase/scripts/diagnose_sbert_mapping.py
python integration_phase/scripts/check_closed_loop_sanity.py
python integration_phase/scripts/run_fairness_checks.py
python -m unittest tests/test_generation_correctness.py
```

The expected inventory is 16 scenario profiles, 469 community playbooks, 4,016
community steps, 4,016 matching CSV/OWL mapping links, and 167 retained generated
playbooks. Mapping checks establish file consistency, not semantic accuracy.
Published hashes are listed in the root README and
[`docs/artifact_manifest.md`](artifact_manifest.md).

## Generation and Reduction

The checked-in MulVAL outputs fix the attack graphs across the `K` sweep:

```bash
for K in 0 1 2 3 4 5 6 7 8 9 10; do
  python integration_phase/scripts/export_generated_playbooks.py \
    --all-cases \
    --limit 500 \
    --cve-table data/scenario_profiles/CVE_MITRE_enriched.scenario.csv \
    --countermeasure-top-k "$K" \
    --skip-cacao \
    --output-dir "results/generated_repository/k_sweep/k_$(printf '%02d' "$K")/export"
done

python integration_phase/scripts/summarize_generation_k_sweep.py \
  --sweep-dir results/generated_repository/k_sweep \
  --k 0 1 2 3 4 5 6 7 8 9 10
```

Each run produces 7,928 playbooks and 72 skipped incidents. Build the paper's
`K=3` repository from its JSONL export:

```bash
python integration_phase/scripts/generated_playbooks_to_owl.py \
  --input-jsonl results/generated_repository/k_sweep/k_03/export/generated_playbooks.jsonl \
  --output-owl results/generated_repository/generated_playbooks.owl \
  --manifest-csv results/generated_repository/generated_playbooks_manifest.csv

python integration_phase/scripts/reduce_generated_playbooks.py \
  --manifest results/generated_repository/generated_playbooks_manifest.csv \
  --owl results/generated_repository/generated_playbooks.owl \
  --strategy hybrid \
  --per-scenario 50
```

The deterministic per-scenario reduction retains 167 playbooks. The value 50
is a cap after exact-signature deduplication and Pareto filtering, not a forced
retention count.

The full `K=3` JSONL and OWL are distributed in the `v0.2` release asset. After
extracting that asset at the repository root, reproduce the diversity table and
TikZ figure with:

```bash
python integration_phase/scripts/analyze_generation_diversity.py
```

## GraphDB and Primary Selection

The default endpoint is
`http://localhost:7200/repositories/incident-response`. Load the ontology,
community corpus, submitted semantic mapping, and retained generated repository:

```bash
python integration_phase/scripts/load_graphdb_files.py --clear \
  selection_phase/source/IncidentResponseSecurityOntology.rdf \
  selection_phase/source/GraphDB/d3fend.owl \
  selection_phase/source/GraphDB/playbooks.owl \
  selection_phase/source/GraphDB/playbook_step_defend_mapping.owl \
  results/generated_repository/corrected_k03/reduced_generated_playbooks.owl

python integration_phase/scripts/verify_graphdb_load.py
```

Run the three reported selection modes:

```bash
python integration_phase/scripts/run_mcdm_selection.py \
  --mode community-only \
  --scoring-profile coverage-only

python integration_phase/scripts/run_mcdm_selection.py \
  --mode generated-reduced \
  --scoring-profile closed-loop-balanced

python integration_phase/scripts/run_mcdm_selection.py \
  --mode augmented-reduced \
  --scoring-profile closed-loop-balanced

python integration_phase/scripts/compare_modes.py
```

Generated candidates are restricted to their source scenario by default. Do
not pass `--allow-cross-scenario-generated` when reproducing the primary result.

## Secondary Analyses

These analyses consume the primary candidate tables unless noted otherwise:

```bash
python integration_phase/scripts/run_selection_profile_comparison.py \
  --coverage-threshold 0.9
python integration_phase/scripts/run_portfolio_selection.py --portfolio-size 3
python integration_phase/scripts/analyze_significance.py \
  --bootstrap-samples 10000 --seed 12345
python integration_phase/scripts/run_weight_sensitivity.py \
  --draws 5000 --concentration 100 --seed 20260714
python integration_phase/scripts/run_ablation_experiments.py
python integration_phase/scripts/analyze_generated_source_selection.py
python integration_phase/scripts/analyze_closed_loop_results.py \
  --generated-steps-csv \
  results/generated_repository/k_sweep/k_03/export/generated_playbook_steps.csv
```

The profile comparison covers closed-loop-balanced, coverage-primary, and the
predefined 90% coverage constraint. The ablation script covers the neutral,
zero, and ignore-and-renormalize missing-value policies and leave-one-criterion-
out variants.

To reproduce the second-run determinism check, rerun the three selection commands
above with `--out-dir results/evaluation/corrected_repeat`, then run:

```bash
python integration_phase/scripts/compare_modes.py \
  --evaluation-dir results/evaluation/corrected_repeat \
  --out-csv results/evaluation/corrected_repeat/closed_loop_comparison.csv
python integration_phase/scripts/check_selection_determinism.py
```

## Reduction Sensitivity

The GraphDB-backed cap analysis builds and evaluates fresh repositories for
`N={5,10,15,25,50}` and restores the 167-playbook repository afterward:

```bash
python integration_phase/scripts/run_corrected_reduction_sensitivity.py \
  --caps 5 10 15 25 50
```

The `v0.2` release also contains the full 7,928-playbook repository and the
predefined 178- and 800-playbook reduction variants. Build the variants with:

```bash
python integration_phase/scripts/build_coverage_reduction_alternatives.py \
  --manifest results/generated_repository/full_k03/generated_playbooks_manifest.csv \
  --owl results/generated_repository/full_k03/generated_playbooks.owl \
  --per-scenario 50
```

For each variant, load its OWL with `load_graphdb_files.py`, then run
`run_mcdm_selection.py` in `generated-reduced` and `augmented-reduced` modes with
that variant's `--generated-owl`, `--reduced-manifest`, and `--out-dir`. This
recomputes pool-relative RC and AC. Summarize the completed runs with:

```bash
python integration_phase/scripts/analyze_source_reduction_experiments.py
```

Restore the primary GraphDB state with the load command in the preceding section.
The release contents and checksums are listed in
[`docs/release_artifacts.md`](release_artifacts.md).

## Publication Tables and Figures

```bash
python integration_phase/scripts/analyze_generation_diversity.py
python integration_phase/scripts/make_weak_profile_figure.py
python integration_phase/scripts/make_corrected_publication_outputs.py
python integration_phase/scripts/build_reproducibility_manifest.py \
  --graphdb-version 10.3.1
```

Publication artifacts are written under
`results/evaluation/corrected/publication_tables/` and
`results/evaluation/corrected/publication_figures/`.

## Interpretation

This is a source-conditioned, source-restricted benchmark. It evaluates
deterministic repository construction, retrieval, and selection on the 16
profiles; it is not a held-out generalization or operational validation study.
