# Playbook Generation and Selection

Reproducibility artifact for:

**Semantic and Provenance-Aware Selection of Incident Response Playbooks through Attack-Graph-Based Repository Enrichment**

The paper was accepted at SecAI 2026 and will be published by Springer in the Computer Security ESORICS 2026 International Workshops proceedings.

## Scope

The implementation transforms structured attack-graph and vulnerability inputs into provenance-rich playbook records, inserts generated and community playbooks into one ontology-backed repository, retrieves candidates through direct ATT&CK provenance and artifact-mediated D3FEND associations, and applies deterministic multi-criteria selection.

The evaluation is a technical and construct-level validation. It does not establish that generated actions are operationally correct, safe, actionable, or effective in a live system. The SBERT links are retrieval associations, not expert-validated semantic ground truth. CVSS-derived risk reduction is model-based, and lifecycle completeness is structural.

## Released Evaluation State

The public result tree contains the evaluation used for the paper:

- 16 source-conditioned ICS scenario profiles;
- 469 community playbooks and 4,016 community steps;
- one submitted top-1 D3FEND mapping for each community step;
- 7,928 generated playbooks for each tested `K`;
- fixed-graph generation sensitivity for `K=0..10`;
- `K=3` reduction from 7,928 to 167 playbooks;
- diversity diagnostics for the full and retained `K=3` generated corpora;
- GraphDB-backed community-only, generated-reduced, and augmented-reduced selection;
- deterministic, fairness, uncertainty, weight, missing-policy, criterion, reduction, coverage-aware, portfolio, and source-selection diagnostics.

### Primary Selection Results

| Repository | Scoring profile | Mean candidates | Generated winners | Community winners | Combined recall | Achievable recall | Normalized recall |
|---|---|---:|---:|---:|---:|---:|---:|
| Community-only | Coverage-only | 105.875 | 0 | 16 | 0.227 | 0.292 | 0.801 |
| Generated-reduced | Closed-loop balanced | 10.438 | 16 | 0 | 0.228 | 0.288 | 0.813 |
| Augmented-reduced | Closed-loop balanced | 116.312 | 10 | 6 | 0.243 | 0.353 | 0.694 |

The augmented-minus-community paired mean combined-recall difference is `0.0158` with bootstrap 95% CI `[-0.0072, 0.0361]` and Holm-adjusted permutation `p=0.375`. Repository augmentation raises mean achievable recall by `0.0602`, with bootstrap 95% CI `[0.0435, 0.0779]`.

Because the community baseline and augmented mode use different declared scoring profiles, their selected-recall difference is a mode/profile comparison, not an isolated causal effect of repository augmentation. Achievable recall is the selector-independent candidate-pool coverage ceiling.

### Coverage-Aware Selection

| Selector | Combined recall | Achievable recall | Normalized recall |
|---|---:|---:|---:|
| Closed-loop balanced top-1 | 0.243 | 0.353 | 0.694 |
| Coverage-primary top-1 | 0.268 | 0.353 | 0.766 |
| 90% coverage-constrained top-1 | 0.265 | 0.353 | 0.758 |
| Greedy portfolio, `K<=3` | 0.350 | 0.353 | 0.994 |

These are outcomes on the bounded 16-profile benchmark, not evidence of generalization to unseen incidents.

### Generation K Sensitivity

All eleven runs use the same checked-in attack graphs, scenario-conditioned CVE table, and `INCIDENT_SEED=1337`.

| K | Mean actions | Direct ATT&CK recall | Relative risk reduction |
|---:|---:|---:|---:|
| 0 | 0.000 | 0.0000 | 0.0000 |
| 1 | 3.817 | 0.2509 | 0.4178 |
| 2 | 5.148 | 0.2509 | 0.4178 |
| 3 | 6.602 | 0.2910 | 0.4426 |
| 4 | 7.802 | 0.3093 | 0.4533 |
| 5 | 9.268 | 0.3563 | 0.4666 |
| 6 | 9.975 | 0.3653 | 0.4666 |
| 7 | 10.875 | 0.3939 | 0.4680 |
| 8 | 11.695 | 0.4067 | 0.4704 |
| 9 | 13.544 | 0.4514 | 0.4720 |
| 10 | 14.478 | 0.4612 | 0.4721 |

The declared rule chooses the smallest `K` within 99% of both maximum direct recall and maximum relative risk reduction. It selects `K=10`. This rule has no action-cost term; `K=10` is therefore a metric-maximizing result, not an operational optimum. The paper configuration remains `K=3`.

### Generation Diversity Diagnostics

The retained `K=3` repository contains 167 playbooks and 13,861 unordered playbook pairs. Pairwise Jaccard distance is calculated over the per-playbook sets for each representation. Shannon entropy is calculated over the occurrence distribution, in bits.

| Representation | Jaccard distance | Shannon entropy |
|---|---:|---:|
| ATT&CK techniques | 0.687 | 4.342 |
| Hosts | 0.000 | 3.322 |
| CVEs | 0.544 | 3.496 |
| Incident-path `(host, CVE, ATT&CK)` triples | 0.928 | 6.780 |

All retained incident paths contain the same ten host identifiers, so their host sets have zero pairwise distance. The nonzero host entropy describes the frequency distribution over those identifiers and is not a set-diversity result. These diagnostics characterize structural variation in the evaluated repository; they do not establish representativeness of operational incidents.

The executable definitions, full 7,928-playbook comparison, and figure source are in `generation_diversity_diagnostics.csv`, `generation_diversity_diagnostics.json`, and `corrected_generation_diversity.tex` under `results/evaluation/corrected/`.

## Repository Layout

```text
data/
  scenario_profiles/              Canonical scenario profiles and CVE table
generation_phase/source/
  AttackTree_generation/          MulVAL execution helper
  Incident_generation/            Attack-path and incident construction
  Response_generation/            Countermeasure and risk model
  defense_techniques/             ATT&CK-artifact-D3FEND mappings
  mulval-inputs/                   Checked-in attack graphs for 16 scenarios
selection_phase/source/
  GraphDB/                         D3FEND, community, and mapping OWL inputs
  Playbook/                        Community playbook corpus and OWL builder
  Playbook-defend-mapping/         SBERT mapping code and submitted mapping
  Use-Case/                        Scenario CSVs and SPARQL target queries
integration_phase/scripts/         Generation, reduction, selection, and analyses
results/generated_repository/      K=3 repository and K=0..10 summary
results/evaluation/corrected/      Evaluation tables and candidate scores
docs/                              Reproduction and artifact manifests
```

## Requirements

- Python 3.14.5 for the recorded environment;
- GraphDB 10.x or an RDF4J-compatible repository endpoint for selection;
- MulVAL only when rebuilding attack graphs instead of using the checked-in
  graph outputs.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-lock.txt
```

`requirements-lock.txt` records the exact core environment used for the evaluation. `requirements.txt` lists the direct dependencies without version constraints for compatible environments.

SBERT mapping regeneration additionally requires:

```bash
python -m pip install -r requirements-optional.txt
```

## Quick Verification

The following commands use checked-in inputs and result tables:

```bash
python integration_phase/scripts/build_ics_scenario_inventory.py
python integration_phase/scripts/audit_semantic_mapping.py
python integration_phase/scripts/check_closed_loop_sanity.py
python integration_phase/scripts/run_fairness_checks.py
python integration_phase/scripts/analyze_significance.py
python integration_phase/scripts/run_weight_sensitivity.py
python -m unittest tests/test_generation_correctness.py
```

Expected integrity results:

- semantic mapping: 4,016 CSV links and 4,016 matching OWL links;
- generated repository: 167 playbooks;
- fairness: zero wrong-scenario generated candidates;
- deterministic rerun: identical candidate IDs, criteria, scores, winners, and recall metrics.

Mapping integrity does not measure mapping accuracy.

## GraphDB Reproduction

Create a GraphDB repository named `incident-response`, then load the evaluated repository:

```bash
python integration_phase/scripts/load_graphdb_files.py --clear \
  selection_phase/source/IncidentResponseSecurityOntology.rdf \
  selection_phase/source/GraphDB/d3fend.owl \
  selection_phase/source/GraphDB/playbooks.owl \
  selection_phase/source/GraphDB/playbook_step_defend_mapping.owl \
  results/generated_repository/corrected_k03/reduced_generated_playbooks.owl

python integration_phase/scripts/verify_graphdb_load.py
```

Run the three primary modes:

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

Generated candidates are source-restricted by default. The primary experiment does not use `--allow-cross-scenario-generated`.

The complete generation, reduction, GraphDB, selection, sensitivity, and publication workflow is in [docs/reproduction.md](docs/reproduction.md).

## Selection Protocol

The fixed heuristic weights are:

```text
DC=0.25  DAC=0.20  DTC=0.20  TC=0.10  RC=0.15  CC=0.07  AC=0.03
```

Missing TC, RC, CC, and AC values receive the declared neutral value `0.5`. DC, DAC, and DTC are zero when absent. The `zero` and `ignore-and-renormalize` policies are included as ablations. Exact top-1 score ties resolve to the lexicographically smallest stable playbook ID.

Definitions, denominator handling, and executable scoring rules are implemented in [selection_protocol.py](integration_phase/scripts/selection_protocol.py).

## SBERT Mapping

The checked-in mapping contains the submitted top-1 associations:

- model family recorded by the original code: `all-MiniLM-L6-v2`;
- original model revision and package version were not recorded in the source snapshot;
- six field similarities with weights `0.1, 0.2, 0.1, 0.2, 0.2, 0.2`;
- weighted cosine-similarity aggregation;
- rejection threshold `0.0`;
- one mapping per step;
- deterministic stable candidate ordering for future reruns.

The mapping CSV, canonical OWL, and verified GraphDB state agree on all 4,016 links. No expert-labelled precision or recall result is claimed.

The optional mapping script uses a pinned model revision for a reproducible new run and writes under `results/semantic_mapping_regeneration/`. It does not overwrite the submitted mapping and is not presented as a reconstruction of the unrecorded original model revision or runtime.

## Large Artifact Release

The Git repository keeps every individual file below 10 MB. Full-pool and alternative repository artifacts are provided separately:

[Artifact release v0.2: semantic-playbook-selection-corrected-large-artifacts-v0.2.tar.gz](https://github.com/Fraunhofer-FIT-DSAI/Playbook_Generation_and_Selection/releases/download/v0.2/semantic-playbook-selection-corrected-large-artifacts-v0.2.tar.gz)

Archive SHA-256:

```text
259c436f112f7ad5dd64e0b2d72e8e29141c2413484755a1c659633c2e781b31
```

The archive includes the unreduced 7,928-playbook K=3 JSONL, step CSV, OWL and manifest; the 178- and 800-playbook alternative repositories; and the cap sensitivity repositories. See [docs/release_artifacts.md](docs/release_artifacts.md).

The original `v0.1` release remains available but is not used by this evaluation.

## Artifact Integrity

| Artifact | SHA-256 |
|---|---|
| Base ontology | `713c08d7f515d21a88f55a9325bed7ac9e34ce1aba9bef1e035ed92be93d085c` |
| D3FEND OWL | `99dc61f4b5464f11efe61ed8be15992c3dfa6bf0805ed641c8d6534ae46af4b1` |
| Community playbooks OWL | `db4ed6b43bc6d76c2c0a15120915828d64471160fbfe914f662ec1dd89864528` |
| Step-D3FEND mapping OWL | `0ffb6cf054324ac5a3cad0787c1c7b25e4eb03daa7a39bc0fafa1e41e18da271` |
| K=3 reduced OWL | `9f7531f9e83ea6bee68bd5ee504098eac5c06fd4595b99be908aaeb5ee755a4d` |
| K=3 manifest | `866acd440d981c54cc997105fb2d0cdc738f88a58588c3aaa3721b4e8efc5e95` |

The full file-level inventory is in
[docs/artifact_manifest.md](docs/artifact_manifest.md).

These hashes identify the distributed files. RDF/XML statement order is not semantic and may differ across serializer runs; compare regenerated ontologies as RDF graphs and compare their playbook manifests, rather than requiring an identical RDF/XML byte order.

## Third-Party Data

MITRE ATT&CK and MITRE D3FEND remain third-party resources and retain their respective terms and notices. The checked-in community corpus is the artifact available with the paper code; complete upstream acquisition URLs, revisions, dates, licenses, and conversion logs were not present in the original snapshot and are reported as unavailable rather than reconstructed.

## Funding note
Funded by the European Union. This work has received funding from the  European High Performance Computing Joint Undertaking (JU) and from the  German Federal Ministry of Research, Technology and Space (BMFTR), the  Ministry of Culture and Science of North Rhine-Westphalia (MKW NRW) and  the Hessian Ministry of Science and Research, Arts and Culture (HMWK)  under grant agreement No 101250682.

