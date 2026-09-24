#!/usr/bin/env bash
# A stored shell script, previewed as highlighted source.
set -euo pipefail

for target in staging production; do
  echo "deploying to ${target}"
done
