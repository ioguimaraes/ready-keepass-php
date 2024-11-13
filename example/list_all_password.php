<?php

require_once __DIR__ . '/../vendor/autoload.php';

use KeePassPHP\KeePassPHP;
use KeePassPHP\Key\CompositeKey;

$file = 'C:/Users/fz388/Documents/EmergencyAccountsLinux.kdbx';
$secret = 'TSBRBrasil#0001';
//$file = __DIR__ . '/../files/Database.kdbx';
//$secret = 'TesteDatabase01';
$err = '';


//Create a composite key
$ckey = new CompositeKey();

//Attach the password key
$ckey->addKey( KeePassPHP::keyFromPassword( $secret ) );

//Open KDBX file
$db = KeePassPHP::openDatabaseFile($file, $ckey, $err);

//Transform file info in Array format - standard view is basic, you can view all info of this file structure setting $basic_view false
$data_file = $db->toArray(false);

//List all UUID Entries
$entry_list = $db->getEntriesUUID($data_file['Root']['Group'], true);

//$processed = array_pop( $entry_list);
//$processed = array_pop( $processed);

print_r($entry_list);
//die;

$password_list = $db->getPasswords($entry_list);
print_r($password_list);
//print_r($db->getPassword('eY5zYpaOgkOq39vubwSGGw=='));