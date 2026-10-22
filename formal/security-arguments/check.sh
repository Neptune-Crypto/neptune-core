#!/usr/bin/env bash
# Builds the Lean library and fails if any theorem uses `sorry` or an axiom
# other than propext, Quot.sound and Classical.choice.
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
echo "all checks passed"
