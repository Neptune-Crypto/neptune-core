#!/usr/bin/env sh

# create a file with name supplied through CLI arguments
mkdir -p "$2"
touch "$2/$1.block"

exit 0
