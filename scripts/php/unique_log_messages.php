#!/usr/bin/env php
<?php

// A simple script to parse a neptune-core log file and dedup log messages
// of a given type  (INFO, WARN, ERROR, DEBUG), or any type if omitted.


$path = @$argv[1];
$type = @$argv[2];

if (!$path) {
    die("please specify a neptune log file and optional log type: INFO | WARN | ERROR | DEBUG");
}

$file = new SplFileObject($path);


$uniques = [];

$type_needle = "$type";

while(!$file->eof()) {
	$line = $file->fgets();
	if($type) {
		if(strstr($line, $type_needle) === false) {
			continue;
		}
	}

	$cut_at = strpos($line, "neptune_cash::");
	if(!$cut_at) {
		continue;
	}

	$shortened = substr($line, $cut_at);

	$sum = md5($shortened);
	if( !@$uniques[$sum] ) {
		$uniques[$sum] = 1;
		echo $line;
	}
}


