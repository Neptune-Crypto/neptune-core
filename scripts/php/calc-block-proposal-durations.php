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
//


date_default_timezone_set("UTC");

$path = @$argv[1];

if (!$path) {
    die("please specify a neptune log file.");
}

// sample lines:  (note: sometimes same event is received multiple times, eg from different peers)
// 2025-02-15T16:07:36.052344541Z  INFO ThreadId(53) neptune_cash::peer_loop: Got new block from peer 51.158.203.7:9798, height 683, mined 2025-02-15T16:07:06.768+00:00
// 2025-02-15T16:21:45.835421687Z  INFO ThreadId(55) neptune_cash::mine_loop: Miner received message about new block proposal for guessing.


$cmd = "cat '$path' | grep -e 'Miner received message about new block proposal' -e 'Got new block from peer'";
$output = shell_exec($cmd);

$lines = explode("\n", $output);

$events = [];

$curr_height = null;
foreach ($lines as $line) {

    // filter non-printable chars
    $line = preg_replace('/\e[[][A-Za-z0-9];?[0-9]*m?/', '', $line);

    if (preg_match(
        "/(.*)..INFO.*Got new block from peer.*, height (.*),/i",
        $line,
        $matches
    )
    ) {
        $timestamp = trim($matches[1]);
        $height = $matches[2];
        $curr_height = $height;
        $events[] = ["type" => 1, "timestamp" => $timestamp, "height" => $height];
    }

    if($curr_height !== null ) {

        if (preg_match(
            "/(.*)..INFO.*Miner received message about new block proposal/i",
            $line,
            $matches
        )
        ) {
            $timestamp = trim($matches[1]);
            $events[] = ["type" => 2, "timestamp" => $timestamp, "height" => $curr_height];
        }
    }
}
//print_r($events); exit;

// remove dup events
$unique_events = [];
foreach ($events as $event) {
    extract($event);
    // ignore dups.  we only need the first of both event types.
    if (!@$unique_events[$height][$type]) {
        $unique_events[$height][$type] = $timestamp;
    }
}

//print_r($unique_events); exit;

if (!count($unique_events)) {
    die("did not find any events.");
}


foreach ($unique_events as $height => $types) {
    $new_block_timestamp = @$types[1];
    $new_block_proposal_timestamp = @$types[2];

    if($new_block_timestamp && $new_block_proposal_timestamp) {
        $from = strtotime($new_block_timestamp);
        $to = strtotime($new_block_proposal_timestamp);
        $duration = $to - $from;
        assert($duration > 0);


        $human_duration = human_time_diff($from, $to);

        echo sprintf("height: %s\t block: %s\t first proposal: %s\t proposal duration: %s\n", $height, format_iso8601_time($new_block_timestamp), format_iso8601_time($new_block_proposal_timestamp), $human_duration);
    }
}

function human_time_diff($from_time, $to_time)
{
    $diff = $to_time - $from_time;

    if ($diff < 0) {
        return "0 seconds"; // Handle negative differences
    }

    $intervals = array(
    'year'   => 31536000,
    'month'  => 2592000,
    'week'   => 604800, 
    'day'    => 86400,
    'hour'   => 3600,
    'minute' => 60,
    'second' => 1
    );

    $ret = array();
    foreach ($intervals as $name => $seconds) {
        if (($count = floor($diff / $seconds)) > 0) {
            $ret[] = $count . ' ' . ($count == 1 ? $name : $name . 's');
            $diff -= ($count * $seconds);
        }
    }

    return implode(', ', $ret);
}

function format_iso8601_time($iso8601_time)
{
    // Extract date and time parts
    $parts = explode('T', $iso8601_time);
    if (count($parts) !== 2) {
        return "Invalid ISO 8601 time";
    }

    list($date, $time) = $parts;

    // Extract date parts
    list($year, $month, $day) = explode('-', $date);

    // Extract time parts
    list($hour, $minute, $second_microseconds) = explode(':', $time);
    list($second, $microseconds) = explode('.', $second_microseconds);

    // Shorten microseconds to 3 decimal places
    $microseconds = substr($microseconds, 0, 2);

    // Construct the formatted time
    $formatted_time = "$year-$month-$day $hour:$minute:$second.$microseconds";

    return $formatted_time;
}


