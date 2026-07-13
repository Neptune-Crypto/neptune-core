#!/usr/bin/env bash
set -euo pipefail

SCRIPT="$HOME/.bash_neptune_cli"
LINE="source $SCRIPT"
FILE="$HOME/.bashrc"

# Ask for bash completions explicitly, so the caller's login shell ($SHELL)
# does not determine the output.
cargo run --bin neptune-cli -- completions --shell bash > "$SCRIPT"

grep -qF -- "$LINE" "$FILE" 2>/dev/null || echo "$LINE" >> "$FILE"
echo "completions installed to $SCRIPT and added to $FILE."
echo "Now please run 'source $FILE'."
