#!/usr/bin/env php
<?php

// This script is useful for finding slow unit tests.
//
// The script sorts the output of `cargo test` by duration of
// each test, and then prints the results in descending order.
//
// It also prints stats at the bottom, eg:
//
// --- unit test stats ---
// Count: 733
// Total: 974.801
// Min:   0.000
// Max:   104.073
// Mean:  1.3298785811733
// Median: 0.118
// ----------------------
//
// As of this writing, it is necessary to use the nightly compiler
// in order to obtain timing for each test.
//
// Here is example usage:
//
// cargo +nightly test -- -Z unstable-options --report-time 2>&1 | tee tests.out
// sort_tests.php tests.out

$file = @$argv[1];

if(!$file || !file_exists($file)) {
    die("please provide a file with output of cargo test, eg:\n cargo +nightly test -- -Z unstable-options --report-time 2>&1 | tee tests.out");
}

$lines = file($file);

$a = [];
foreach($lines as $line) {
	$fields = explode(' ', $line);
	$key = $fields[count($fields)-1];
	$key_new = trim(str_replace(['<', '>', 's'], '', $key));
	if($key_new != $key && is_numeric($key_new) && substr($line, 0, 5) == "test " && !strstr($line, "finished in")) {
		$a[$line] = $key_new;
	} else {
//		echo "skipping $line";
	}
}

arsort($a);

foreach($a as $line => $time) {
	echo $line ;
}

echo "\n\n\n";
analyze_float_array(array_values($a));



function analyze_float_array(array $numbers): void {
    if (empty($numbers)) {
        echo "Error: The input array is empty. Cannot calculate statistics.\n";
        return;
    }

    // --- Min and Max ---
    $min = min($numbers);
    $max = max($numbers);

    // --- Mean (Average) ---
    $sum = array_sum($numbers);
    $count = count($numbers);
    $mean = $sum / $count;

    // --- Median ---
    // 1. Sort the array numerically.
    sort($numbers);

    // 2. Determine the middle index(es).
    $middleIndex = floor($count / 2);

    if ($count % 2 === 1) {
        // Odd number of elements: median is the middle element.
        $median = $numbers[$middleIndex];
    } else {
        // Even number of elements: median is the average of the two middle elements.
        $median = ($numbers[$middleIndex - 1] + $numbers[$middleIndex]) / 2;
    }

    // --- Print Results ---
    echo "--- unit test stats ---\n";
    echo "Count: " . $count . "\n";
    echo "Total: " . $sum . "\n";
    echo "Min:   " . $min . "\n";
    echo "Max:   " . $max . "\n";
    echo "Mean:  " . $mean . "\n";
    echo "Median: " . $median . "\n";
    echo "----------------------\n";
}

