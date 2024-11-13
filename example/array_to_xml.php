<?php

require_once __DIR__ . '/../vendor/autoload.php';

use KeePassPHP\KeePassPHP;
use KeePassPHP\Lib\Database;

$file = json_decode(file_get_contents(__DIR__ . '/../files/array_full.data'), true);

//Set Standard XML file
$db = Database::setStandardFile(file_get_contents(__DIR__ . "/../files/standard.xml"));

//Transform array in xml
$data_xml = $db->toXML($file, $err);
print_r(KeePassPHP::formatXML($data_xml));