<?php

require_once 'vendor/autoload.php';

use KeePassPHP\KeePassPHP;
use KeePassPHP\Key\CompositeKey;
use KeePassPHP\Lib\Database;

$file = 'C:/Users/fz388/Documents/EmergencyAccountsLinux.kdbx';
$new_f = 'C:/Users/fz388/Documents/EmergencyAccountsLinux_new.dat';
$secret = 'TSBRBrasil#0001';
$err = '';

//Create a composite key
$ckey = new CompositeKey();

//Attach the password key
$ckey->addKey( KeePassPHP::keyFromPassword( $secret ) );

//$newPass = KeePassPHP::addPassword($ckey, 'teste#1111');

//Open the databsae file
$db = KeePassPHP::openDatabaseFile($file, $ckey, $err);
//$db->setPasswordArray('eY5zYpaOgkOq39vubwSGGw==', 'testNewPassword#0000');
//print_r($db->getPassword('eY5zYpaOgkOq39vubwSGGw=='));
$groups = $db->toArray(false);
$customer_list = array_column($groups['Root']['Group'][0]['Group'][0]['Group'], 'Name');
//print_r($groups['Root']['Group'][0]['Group'][0]['Group']);
//print_r($customer_list);
//die;

$kdbx_xml = $db->getContentXML();
$kdbx_random_stream = $db->getRandomStream();



$new_xml = $db->toXML($groups, $kdbx_xml, $kdbx_random_stream, $err);


$encrypt_file = KeePassPHP::encryptInKdbx($new_xml, $ckey, 8, $err);
$decrypt_file = KeePassPHP::decryptFromKdbx($encrypt_file, $ckey, true, $err);
print_r($decrypt_file);
die;

$fp = fopen($new_f, 'w');
fputs($fp, $encrypt_file);
fclose($fp);