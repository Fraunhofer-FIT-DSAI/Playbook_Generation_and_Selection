# Large Artifact Release

## Release

- Tag: `v0.2`
- Asset:
  `semantic-playbook-selection-corrected-large-artifacts-v0.2.tar.gz`
- Size: approximately 18 MB compressed, 681 MB extracted
- SHA-256:
  `259c436f112f7ad5dd64e0b2d72e8e29141c2413484755a1c659633c2e781b31`

Download:

<https://github.com/Fraunhofer-FIT-DSAI/Playbook_Generation_and_Selection/releases/download/v0.2/semantic-playbook-selection-corrected-large-artifacts-v0.2.tar.gz>

Extract at the repository root:

```bash
tar -xzf semantic-playbook-selection-corrected-large-artifacts-v0.2.tar.gz \
  --strip-components=1
shasum -a 256 -c SHA256SUMS
```

## Contents

`results/generated_repository/full_k03/`

- 7,928-playbook normalized JSONL;
- generated step CSV;
- missing-provenance and skipped-incident diagnostics;
- unreduced generated OWL;
- unreduced generated manifest.

`results/evaluation/corrected/reduction_alternatives/`

- 178-playbook coverage-preserving repository;
- 800-playbook marginal-coverage repository;
- manifests, reducer reports, and summaries.

`results/evaluation/corrected/reduction_sensitivity/`

- exact generated OWL, manifest, report, and summary for caps
  `5, 10, 15, 25, 50`.

## Key Hashes

| Artifact | SHA-256 |
|---|---|
| Unreduced K=3 OWL | `719ca0c9c8623a2be44a20a715f615790d24c7162dfe3fa88cd715d0917ce396` |
| Unreduced K=3 manifest | `3f939078ba443e8418f91fc8ceb91ad0acfc35a8396fce31bf7fdfc552423ba9` |
| Coverage-preserving OWL | `d8f7f38b7cc08053bcdbb56f7eb0c101ffed814355a6cf918130ec858736bf01` |
| Coverage-preserving manifest | `93b30e57efaec9c29a370f209608eb7ca3d23c080740cf7907cda7f3125bc5a1` |
| Marginal-coverage OWL | `6cd8b9bb66f21e9d3699cb5c49a426250f07d4e2f5514d8e3bfaee57ab747ace` |
| Marginal-coverage manifest | `3bd1a59fe9837f2c8db393fae87925d2e784515a628556eb8c36fed844785dd1` |

The archive contains `SHA256SUMS` for every included file.
