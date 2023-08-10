<?php

require_once 'vendor/autoload.php';

use KeePassPHP\KeePassPHP;
use KeePassPHP\Key\CompositeKey;
use KeePassPHP\Lib\Database;

$file = 'C:/Users/fz388/Documents/EmergencyAccountsLinux.kdbx';
$new_f = 'C:/Users/fz388/Documents/EmergencyAccountsLinux_new.xml';
$secret = 'TSBRBrasil#0001';
$err = '';

//Create a composite key
$ckey = new CompositeKey();

//Attach the password key
$ckey->addKey( KeePassPHP::keyFromPassword( $secret ) );

//$newPass = KeePassPHP::addPassword($ckey, 'teste#1111');

//Open the databsae file
$db = KeePassPHP::openDatabaseFile($file, $ckey, $err);
$groups = $db->toArray();
print_r($groups);
die;

$kdbx_xml = $db->getContentXML();
$kdbx_random_stream = $db->getRandomStream();



$new_xml = $db->toXML($groups, $kdbx_xml, $kdbx_random_stream, $err);


//$new_file = Database::loadFromArray($groups, 1,$err);

$encrypt_file = KeePassPHP::encryptInKdbx($new_xml, $ckey, 8, $err);
print_r(KeePassPHP::decryptFromKdbx($encrypt_file, $ckey, true, $err));
die;

$fp = fopen($new_f, 'w');
fputs($fp, $new_xml);
fclose($fp);