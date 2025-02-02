#!/usr/bin/env bash
#
CMD=./target/debug/neptune-cli

$CMD --port 19790 shutdown 
$CMD --port 19791 shutdown
$CMD --port 19792 shutdown
