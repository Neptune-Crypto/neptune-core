#!/usr/bin/env php
<?php

// A simple script to parse a neptune-core log file and count how many times a
// lock was acquired and released for each location (acquired)
//
// If a discrepancy is found between number of acquire and release, it is
// reported.  This typically indicates a lock that is not being released and
// thus is the cause of a hang/deadlock.
//
// note that neptune-core must be built with --features log-lock_events.  if
// not, it will not emit the necessary log messages.


$path = @$argv[1];

if (!$path) {
    die("please specify a neptune log file.");
}

$lines = file($path);

$locations = [];

// sample line:
//        |-- lock_event=Acquire { info: LockInfo { name: Some("RustyWalletDatabase-Schema"), lock_type: RwLock }, acquisition: Read, try_acquire_at: Some(Instant { tv_sec: 25730099, tv_nsec: 617232523 }), acquire_at: Some(Instant { tv_sec: 25730099, tv_nsec: 617348321 }), location: Some(Location { file: "/data/neptune-core/neptune-core/src/database/storage/storage_schema/dbtvec_private.rs", line: 136, col: 57 }) }

foreach ($lines as $line) {
    if (strpos($line, "lock_event") === false) {
        continue;
    }

    if (
        preg_match(
            "/lock_event[^TAR]*(.*) \{ info.*acquisition: (.*),.*Location \{(.*)\}/i",
            $line,
            $matches
        )
    ) {
        $event = $matches[1];
        $type = $matches[2];
        $location = $matches[3];

        @$locations[$location][$event] += 1;
    }
}

foreach ($locations as $location => $events) {
    foreach ($events as $event => $count) {
        echo "$count $event at $location\n";
    }
    echo "\n";
}

if (!count($locations)) {
    die( "did not find any lock events. Was neptune-core compiled with --features log-lock_events?");
}

echo "\n\n------------------\n\n";

foreach ($locations as $location => $events) {
    $acquires = @$events["Acquire"];
    $releases = @$events["Release"];
    if ($acquires != $releases) {
        echo "Acquire/Release mismatch for $location\n";
        echo " acquires: $acquires\n";
        echo " releases: $releases\n";
    }
}

