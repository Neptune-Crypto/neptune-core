#!/usr/bin/env bash
#
# Restart alphanet balance and delete all chain data

set -e

read -p "Are you sure you want to reset your balance for alphanet? [y/n]" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "Assuming you are on Linux and use default data directory. Is that the case? If not, please answer *no* now."
    read -p "Are you *completely* sure you want to reset your balance? [y/n]" -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
	timestamp=$(date +%s)
	rm -rf ~/.local/share/neptune/alpha/blocks/
	rm -rf ~/.local/share/neptune/alpha/databases/
	wallet_dir="$HOME/.local/share/neptune/alpha/wallet"
	old_ir_path="$wallet_dir"/incoming_randomness.dat
	old_or_path="$wallet_dir"/outgoing_randomness.dat
	backups_dir="$wallet_dir"/backups/
	mkdir -p "$backups_dir"

	new_ir_path="$backups_dir"_old_incoming_randomness_backup_"$timestamp".dat
	new_or_path="$backups_dir"_old_outgoing_randomness_backup_"$timestamp".dat
	mv "$old_ir_path" "$new_ir_path"
	mv "$old_or_path" "$new_or_path"
	echo
	echo "Moved old incoming and outgoing randomness to" "$backups_dir"
    fi
fi
