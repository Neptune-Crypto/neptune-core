#!/usr/bin/env bash
set -euo pipefail

# zsh loads completion functions from directories on its `fpath`, so unlike the
# bash installer we drop the generated `_neptune-cli` function into such a
# directory and make sure the directory is on `fpath` and that `compinit` runs.
COMP_DIR="$HOME/.zsh/completions"
FILE="$HOME/.zshrc"

mkdir -p "$COMP_DIR"
cargo run --bin neptune-cli -- completions --shell zsh > "$COMP_DIR/_neptune-cli"

add_line() { grep -qF -- "$1" "$FILE" 2>/dev/null || echo "$1" >> "$FILE"; }
# `fpath` must be extended before `compinit` runs, so append in this order.
add_line "fpath=($COMP_DIR \$fpath)"
add_line "autoload -Uz compinit && compinit"

echo "completions installed to $COMP_DIR/_neptune-cli and configured in $FILE."
echo "Now please run 'source $FILE' (or restart your shell)."
