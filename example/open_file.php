<?php

require_once __DIR__ . '/../vendor/autoload.php';

use KeePassPHP\KeePassPHP;
use KeePassPHP\Key\CompositeKey;

$file = __DIR__ . '/../files/Database.kdbx';
$secret = 'TesteDatabase01';
$err = '';


//Create a composite key
$ckey = new CompositeKey();

//Attach the password key
$ckey->addKey( KeePassPHP::keyFromPassword( $secret ) );

//Open KDBX file
$db = KeePassPHP::openDatabaseFile($file, $ckey, $err);
print_r($db);

//Transform file info in Array format - standard view is basic, you can view all info of this file structure setting $basic_view false
$data_file = $db->toArray(false);
print_r($data_file);