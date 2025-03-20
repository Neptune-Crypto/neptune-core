#!/bin/bash
#
# Backup node's randomness for fund recovery.

# Copy to ~/bin/, then you can set this script to run daily by opening `crontab -e`
# and adding this line:
# 0 3 * * * ~/bin/backup-neptune-core-randomness.sh
# This will run the script daily, at 3am.
# Make sure the command works by running this script manually first though,
# after filling out the missing pieces below.
# Don't forget to also backup your seed phrase!! This script does *not* handle
# the backing up of `wallet.dat`.
rsync -av --backup --suffix=_$(date +'%Y-%m-%d_%H-%M-%S') \
      --backup-dir=~/neptune-core-mainnet-randomness-backup/<machine-id>/$(date +'%Y-%m-%d') \
      ~/.local/share/neptune/main/wallet/incoming_randomness.dat ~/.local/share/neptune/main/wallet/outgoing_randomness.dat <user>@<remote-server>:~/neptune-core-mainnet-randomness-backup/<machine-id>/
