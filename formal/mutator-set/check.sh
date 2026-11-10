#!/usr/bin/env bash
# Builds the Lean library, checks axioms, and checks that the committed test
# vectors are exactly what the Lean model generates.
set -euo pipefail
cd "$(dirname "$0")"
lake build
out=$(lake env lean CheckAxioms.lean)
echo "$out"
if echo "$out" | grep -E "sorryAx" >/dev/null; then echo "error: a theorem depends on sorry"; exit 1; fi
if echo "$out" | grep -oE "axioms: \[[^]]*\]" | tr -d '[]' | sed 's/axioms: //' | tr ',' '\n' \
   | sed 's/ //g' | grep -vE '^(propext|Quot.sound|Classical.choice)?$' >/dev/null; then
  echo "error: a theorem depends on a non-standard axiom"; exit 1
fi
cp vectors/aocl_range.csv /tmp/aocl_range.committed.csv
lake exe genvectors
diff -q /tmp/aocl_range.committed.csv vectors/aocl_range.csv
echo "all checks passed"
