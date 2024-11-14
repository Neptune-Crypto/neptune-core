#!/usr/bin/env php

<?php

$path = @$argv[1];

if(!$path) die("please specify a neptune log file.");

$lines = file($path);

$found = [];

// sample line:
// 2024-11-02T20:53:45.472275Z  WARN reorganization_does_not_crash_mempool: neptune_core::locks::tokio::atomic_rw: write-lock held for 4.1489367 seconds. (exceeds max: 100 milli)  location: src/models/state/mod.rs:216:14

foreach($lines as $line) {
    if(strpos($line, "lock held for") === false) {
        continue;
    }

    if (preg_match("/for (.*) seconds/i", $line, $matches)) {
        $secs = $matches[1];
        $found[$secs] = $line;
    }
}

krsort($found);

foreach($found as $line) {
    echo $line . "\n";
}

