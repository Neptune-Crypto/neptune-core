#!/usr/bin/env bash
set -euo pipefail

# fish auto-loads completions from files named `<command>.fish` in its
# completions directory, so no shell-rc edit or `source` line is needed.
COMP_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"

mkdir -p "$COMP_DIR"
cargo run --bin neptune-cli -- completions --shell fish > "$COMP_DIR/neptune-cli.fish"

echo "completions installed to $COMP_DIR/neptune-cli.fish."
echo "Restart fish (or run 'source $COMP_DIR/neptune-cli.fish') to activate."
