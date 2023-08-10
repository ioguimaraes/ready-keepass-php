This is a fork of [KeePassPHP](https://github.com/julienblitte/KeePassPHP).
===

Changes
---
* Refactor the project to use PSR-4 Autoloading
* Implement the handling of Binary (attachments in KeePass) in **Meta**, as well as references in **Entry** tags.

Usage
---
```php

require_once '../vendor/autoload.php';

use KeePassPHP\KeePassPHP;
use KeePassPHP\Key\CompositeKey;
use KeePassPHP\Lib\Database;

$file = '/path/to/your/file.kdbx';
$secret = 'YouKdbxPassword';

//Store any error messages
$err = '';
//Create a composite key
$ckey = new CompositeKey();
//Attach the password key
$ckey->addKey( KeePassPHP::keyFromPassword( $secret ) );
//Open the databsae file
/** @var Database $db */
$db = KeePassPHP::openDatabaseFile($file, $ckey, $err);
//Iterate the list of binaries
foreach($db->getBinaries() as $binary) {
    echo $binary->getContent() ."\r\n---\r\n";
}
```

