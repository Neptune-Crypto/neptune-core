#!/usr/bin/env bash
#
CMD=./target/debug/neptune-cli

$CMD --server-addr 127.0.0.1:19790 shutdown 
$CMD --server-addr 127.0.0.1:19791 shutdown
$CMD --server-addr 127.0.0.1:19792 shutdown
