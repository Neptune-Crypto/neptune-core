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


// $cmd = "cat '$path' | grep -e 'Miner received message about new block proposal' -e 'Got new block from peer'";
// $output = shell_exec($cmd);

$file = new SplFileObject($path);

$events = [];

$curr_height = null;
while(!$file->eof()) {
    $line = $file->fgets();

    if(strpos($line, 'block') === false) {
        continue;
    }


    // filter non-printable chars
    $line = preg_replace('/\e[[][A-Za-z0-9];?[0-9]*m?/', '', $line);

    if (preg_match(
        "/(.*)..DEBUG.*Got new block from peer.*, height (.*),/i",
        $line,
        $matches
    )
    ) {
        $timestamp = trim($matches[1]);
        $height = $matches[2];
        $curr_height = $height;
        $events[] = ["type" => 1, "timestamp" => $timestamp, "height" => $height];
    }


    if (preg_match(
        "/(.*)..INFO.*Guessing with.*on block (.*) with/i",
        $line,
        $matches
    )
    ) {
        $timestamp = trim($matches[1]);
        $height = trim($matches[2]);
        $events[] = ["type" => 2, "timestamp" => $timestamp, "height" => $height];
    }


    if($curr_height !== null ) {

        if (preg_match(
            "/(.*)..INFO.*Miner received message about new block proposal/i",
            $line,
            $matches
        )
        ) {
            $timestamp = trim($matches[1]);
            $events[] = ["type" => 3, "timestamp" => $timestamp, "height" => $curr_height+1];
        }
    }
}
// print_r($events); exit;

// remove dup events
$unique_events = [];
foreach ($events as $event) {
    extract($event);
    // ignore dups.  we only need the first of each event type.
    if (!@$unique_events[$height][$type]) {
        $unique_events[$height][$type] = $timestamp;
    }
}

//print_r($unique_events); exit;

if (!count($unique_events)) {
    die("did not find any events.");
}

$min_duration_width = strlen("03 mins, 22 secs");

//$prev_block_proposal_timestamp = null;
$prev_block_timestamp = null;

foreach ($unique_events as $height => $types) {
    $new_block_timestamp = @$types[1];
    $prev_block_proposal_timestamp = @$types[2] ?: @$types[3];  // we prefer type 2 log message to 3.

    if($new_block_timestamp && $prev_block_proposal_timestamp) {
        $from = $prev_block_timestamp ? strtotime($prev_block_timestamp) : null;
        $to = strtotime($prev_block_proposal_timestamp);

        //        $duration = $to - $from;
        //        assert($duration > 0);

        $guessing_from_timestamp = $prev_block_proposal_timestamp ?: $prev_block_timestamp;

        $guessing_from = $guessing_from_timestamp ? strtotime($guessing_from_timestamp) : null;
        $guessing_to = strtotime($new_block_timestamp);

        $human_duration = $from ? str_pad(human_time_diff($from, $to), $min_duration_width) : str_pad("???", $min_duration_width);
        $human_guessing_duration = $guessing_from ? human_time_diff($guessing_from, $guessing_to) : "???";

        echo sprintf("height: % 5d  arrived: %s  composed: %s  composing: %s  guessing: %s\n", $height, format_iso8601_time($new_block_timestamp), format_iso8601_time($prev_block_proposal_timestamp), $human_duration, $human_guessing_duration);
    } else if ($new_block_timestamp) {
        echo sprintf("height: % 5s  arrived: %s  ** no block proposal received **\n", $height, format_iso8601_time($new_block_timestamp));
    }

    $prev_block_timestamp = $new_block_timestamp;
}

function human_time_diff($from_time, $to_time)
{
    $diff = $to_time - $from_time;

    if ($diff < 0) {
        return " 0 secs"; // Handle negative differences
    }

    $intervals = array(
    'year'   => 31536000,
    'month'  => 2592000,
    'wk'   => 604800,
    'day'    => 86400,
    'hr'   => 3600,
    'min' => 60,
    'sec' => 1
    );

    $ret = array();
    foreach ($intervals as $name => $seconds) {
        if (($count = floor($diff / $seconds)) > 0) {
            $ret[] = sprintf('%02d', $count) . ' ' . $name . 's';
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
