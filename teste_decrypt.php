<?php

require_once 'vendor/autoload.php';

use KeePassPHP\KeePassPHP;
use KeePassPHP\Key\CompositeKey;
use KeePassPHP\Lib\Database;
use KeePassPHP\Util\Reader\ResourceReader;

$file = 'C:/Users/fz388/Documents/EmergencyAccountsLinux_new.dat';
$secret = 'TSBRBrasil#0001';
$err = '';

//Create a composite key
$ckey = new CompositeKey();

//Attach the password key
$ckey->addKey( KeePassPHP::keyFromPassword( $secret ) );

$fp = file_get_contents($file);
//$reader = ResourceReader::openFile($file);
//$db = KeePassPHP::openDatabaseFile($file, $ckey, $err);
$decrypt_file = KeePassPHP::decryptFromKdbx($fp, $ckey, true, $err);

print_r($decrypt_file['db_intance']->toArray(false));