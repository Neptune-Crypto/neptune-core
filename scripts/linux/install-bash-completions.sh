set -e

SCRIPT="$HOME/.bash_neptune_cli"
LINE="source $SCRIPT"
FILE="$HOME/.bashrc"

cargo run --bin neptune-cli -- completions > $SCRIPT
grep -qF -- "$LINE" "$FILE" || echo "$LINE" >> "$FILE"
source $SCRIPT
echo "completions installed to $SCRIPT and added to $FILE."
echo "Now please run 'source $FILE'."

