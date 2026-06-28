#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

SECONDS=0

python3 input_generation/networks.py "$@"
./AttackTree_generation/mulval_pipeline.py "$PWD/mulval-inputs"

duration=$SECONDS
echo "Total execution time: $((duration / 60)) minutes and $((duration % 60)) seconds"
