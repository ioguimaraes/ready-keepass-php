<?php


namespace KeePassPHP;

use DOMDocument;
use Exception;
use KeePassPHP\Filters\IFilter;
use KeePassPHP\Kdbx\KdbxFile;
use KeePassPHP\Key\CompositeKey;
use KeePassPHP\Key\IKey;
use KeePassPHP\Key\KeyFromFile;
use KeePassPHP\Key\KeyFromPassword;
use KeePassPHP\Lib\Database;
use KeePassPHP\Util\FileManager;
use KeePassPHP\Util\Reader\ResourceReader;
use KeePassPHP\Util\Reader\StringReader;

/**
 * Main entry point of the KeePassPHP application.
 * Exposes the high-level API of KeePassPHP.
 */
abstract class KeePassPHP
{
    static public $debugData = "";
    static public $debug = false;

    static private $_started = false;
    /**
     * @var FileManager|null
     */
    static private $_kphpdbManager = null;
    /**
     * @var FileManager|null
     */
    static private $_databaseManager = null;
    /**
     * @var FileManager|null
     */
    static private $_keyManager = null;

    const PREFIX_KPHPDB = "kphpdb";
    const PREFIX_DATABASE = "db";
    const EXT_KDBX = "kdbx";
    const PREFEXT_KEY = "key";

    const DEFAULT_DATA_DIR = "data/";

    const DIR_DATABASE = "db/";
    const DIR_KPHPDB = "kphpdb/";
    const DIR_KEY = "key/";

    const IV_SIZE = 32;
    const DBTYPE_KDBX = 1;
    const KEY_PWD = 1;
    const KEY_FILE = 2;

    const IDX_DBTYPE = 0;
    const IDX_HASHNAME = 1;
    const IDX_KEYS = 2;
    const IDX_WRITEABLE = 3;
    const IDX_ENTRIES = 4;
    const IDX_COUNT = 5;

    /**
     * The version of the API exposed by this version of KeePassPHP.
     */
    const API_VERSION = 1;

    /**
     * Starts the KeePassPHP application. This method must be called before all
     * high-level methods of this class. If $debug is true, debug data will be
     * added to the static variable self::$debugData (especially when an error
     * occurs).
     * @param string $dataDir Relative path to the KeePassPHP data directory. If null,
     *                 the default directory ./data/ is used.
     * @param boolean $debug True to enable debug mode, false otherwise.
     * @return bool
     */
    public static function init($dataDir = null, $debug = false)
    {
        if (self::$_started)
            return true;

        self::$debug = $debug;

        if (!defined("PHP_VERSION_ID") || PHP_VERSION_ID < 50300) {
            self::addDebug("PHP version must be >= 5.3 to run KeePassPHP.");
            return false;
        }
        if (!extension_loaded("hash")) {
            self::addDebug("hash must be loaded to use KeePassPHP.");
            return false;
        }
        if (PHP_VERSION_ID >= 50400 && extension_loaded("openssl")) {
            self::addDebug("KeePassPHP will use the OpenSSL extension.");
        } else if (!extension_loaded("mcrypt")) {
            self::addDebug("No suitable cryptography extension found.");
            return false;
        } else if (!defined("MCRYPT_RIJNDAEL_128")) {
            self::addDebug("Rijndael 128 is not supported by your libmcrypt (it is probably too old).");
            return false;
        } else {
            self::addDebug("KeePassPHP will use the Mcrypt extension.");
            if (PHP_VERSION_ID >= 70100) {
                self::addDebug("The Mcrypt extension is deprecated since PHP 7.1. KeePassPHP will use it anyway, but consider installing OpenSSL.");
            }
        }

        if ($dataDir === null)
            $dataDir = dirname(__FILE__) . '/' . self::DEFAULT_DATA_DIR;
        else
            $dataDir = rtrim($dataDir, '/') . '/';

        self::$_kphpdbManager = new FileManager(
            $dataDir . self::DIR_KPHPDB, self::PREFIX_KPHPDB, true, false);
        self::$_databaseManager = new FileManager(
            $dataDir . self::DIR_DATABASE, self::PREFIX_DATABASE, true, false);
        self::$_keyManager = new FileManager(
            $dataDir . self::DIR_KEY, self::PREFEXT_KEY, true, false);

        self::$_started = true;
        self::addDebug("KeePassPHP application started.");
        return true;
    }

    /****************************
     * Debug and error handling *
     ****************************/

    /**
     * Adds $e to the debug data if debug mode is on.
     * @param Exception $e An exception.
     */
    public static function raiseError(Exception $e)
    {
        if (self::$debug)
            self::$debugData .= "Exception at " . basename($e->getFile()) . ":"
                . $e->getLine() . ": " . self::makePrintable($e->getMessage())
                . "\n";
    }

    /**
     * Adds $msg to the debug data if debug mode is on.
     * @param string $msg A printable string.
     */
    public static function addDebug($msg)
    {
        if (self::$debug)
            self::$debugData .= self::makePrintable($msg) . "\n";
    }

    /**
     * Adds $msg, then $bin in hexadecimal, to the debug data.
     * @param string $msg A printable string.
     * @param string $bin A binary string.
     */
    public static function addDebugHexa($msg, $bin)
    {
        if (self::$debug)
            self::$debugData .= self::makePrintable($msg) . ": " .
                self::strToHex($bin) . "\n";
    }

    /**
     * Adds $msg, then $var (with print_r), to the debug data.
     * @param string $msg A printable stirng.
     * @param mixed $var An object or a value.
     */
    public static function addVar($msg, $var)
    {
        if (self::$debug) {
            self::$debugData .= self::makePrintable($msg) . ": " .
                self::makePrintable(print_r($var, true)) . "\n";
        }
    }

    /**************************
     * Util string operations *
     **************************/

    /**
     * Computes the hexadecimal form of the bytes of $str.
     * @param string $str A string.
     * @return string A string of all hexadecimal codes of bytes of $str.
     */
    public static function strToHex($str)
    {
        $r = "";
        $l = strlen($str);
        for ($i = 0; $i < $l; $i++)
            $r .= str_pad(strtoupper(dechex(ord($str[$i]))), 2, " ",
                    STR_PAD_LEFT) . " ";
        return $r;
    }

    /**
     * Makes the string $s HTML-printable.
     * @param string $s An UTF-8 string.
     * @return string A sanitized string.
     */
    public static function makePrintable($s)
    {
        return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Extracts a subpart of the input string if it long enough.
     * @param string $pwd A password, that should be longer than 4 characters.
     * @return string A subpart of the input string.
     */
    public static function extractHalfPassword($pwd)
    {
        $l = strlen($pwd);
        if ($l < 4)
            return $pwd;
        else
            return substr($pwd, 0, intval(floor($l / 2)));
    }

    /**********************************
     * High-level database management *
     **********************************/

    /**
     * Tries to decrypts the database of id $dbid, and extracts the password
     * of the entry whose uuid is $uuid from it.
     * @param string $dbid A database ID.
     * @param string $kphpdbPwd The password of the KphpDB file.
     * @param string $dbPwd The password of the database file.
     * @param string $uuid An entry uuid in base64.
     * @return string The password as a string, or null in case of error.
     * @throws Exception
     */
    public static function getPassword($dbid, $kphpdbPwd, $dbPwd, $uuid)
    {
        $db = self::getDatabase($dbid, $kphpdbPwd, $dbPwd, true);
        return $db == null ? null : $db->getPassword($uuid);
    }

    /**
     * Gets the database of id $dbid from the internal KeePassPHP database.
     * It may be a cached version with less data (e.g no passwords), but
     * cheaper to decrypt.
     * @param string $dbid A database ID.
     * @param string $kphpdbPwd The password of the KphpDB file.
     * @param string $dbPwd The password of the database file (may be unused if a
     *               cached version exists and if $full is false).
     * @param boolean $full Whether the real, full database file must be returned.
     *              Otherwise, the cached version will be returned if it exists.
     * @return Database A Database instance, or null if an error occured.
     * @throws Exception
     */
    public static function getDatabase($dbid, $kphpdbPwd, $dbPwd, $full)
    {
        if (!self::$_started) {
            self::addDebug("KeepassPHP is not started!");
            return null;
        }

        try {
            $kphpdb = self::openKphpDB($dbid, $kphpdbPwd);

            $db = null;
            if (!$full && $kphpdb->getDBType() == KphpDB::DBTYPE_KDBX) {
                $db = $kphpdb->getDB();
                if ($db != null)
                    return $db;
            }

            $dbContent = self::$_databaseManager->getContent(
                $kphpdb->getDBFileHash());
            if (empty($dbContent))
                throw new KeePassPHPException("Database file not found (hash = "
                    . $kphpdb->getDBFileHash() . ")");

            $rawKey = null;
            $keyFileHash = $kphpdb->getKeyFileHash();
            if (!empty($keyFileHash)) {
                $rawKey = self::$_keyManager->getContent($keyFileHash);
                if ($rawKey == null)
                    throw new KeePassPHPException("Key file not found (ID = "
                        . $dbid . ")");
            }
            return self::openDatabase($dbContent, $dbPwd, $rawKey);
        } catch (KeePassPHPException $exception) {
            self::raiseError($exception);
            return null;
        }
    }

    /**
     * Adds a database to the internal KeePassPHP database, with the id $dbid.
     * $dbid must not exist already. A cached version with less data (e.g no
     * passwords), but cheaper to decrypt, may be stored as well.
     * @param string $dbid A database ID.
     * @param string $dbFile The path of the KeePass database file.
     * @param string $dbPwd The password of the database file.
     * @param string $dbKeyFile The path of a key file for the database file, if
     *                   applicable (use null otherwise).
     * @param KphpDB $kphpdbPwd A password to use to create the KphpDB file.
     * @param boolean $cache Whether to also create a cached version cheaper to decrypt
     *               (using $filter to select the data stored in it).
     * @param IFilter $filter A filter to select what is stored in the cached database
     *                (if null, it will store everything except from passwords).
     * @return true in case of success, false otherwise.
     * @throws Exception
     */
    public static function addDatabaseFromFiles($dbid, $dbFile, $dbPwd,
                                                $dbKeyFile, $kphpdbPwd, $cache, IFilter $filter = null)
    {
        if (empty($dbFile)) {
            self::raiseError(new KeePassPHPException('$dbFile is empty'));
            return false;
        }
        return self::addDatabase($dbid, file_get_contents($dbFile), $dbPwd,
            empty($dbKeyFile) ? null : file_get_contents($dbKeyFile),
            $kphpdbPwd, $cache, $filter);
    }

    /**
     * Adds a database to the internal KeePassPHP database, with the id $dbid.
     * $dbid must not exist already. A cached version with less data (e.g no
     * passwords), but cheaper to decrypt, may be stored as well.
     * @param string $dbid A database ID.
     * @param string $dbContent The content of the KeePass database file, as a string.
     * @param string $dbPwd The password of the database file.
     * @param string $dbKeyContent The content of a key file for the database file, as
     *                      a string (if applicable; use null otherwise).
     * @param KphpDB $kphpdbPwd A password to use to create the KphpDB file.
     * @param boolean $cache Whether to also create a cached version cheaper to decrypt
     *               (using $filter to select the data stored in it).
     * @param IFilter $filter A filter to select what is stored in the cached database
     *                (if null, it will store everything except from passwords).
     * @return boolean true in case of success, false otherwise.
     * @throws Exception
     */
    public static function addDatabase($dbid, $dbContent, $dbPwd,
                                       $dbKeyContent, $kphpdbPwd, $cache, IFilter $filter = null)
    {
        if (!self::$_started) {
            self::addDebug("KeepassPHP is not started!");
            return false;
        }

        $dbHash = null;
        $keyFileHash = null;
        try {
            if (self::$_kphpdbManager->existsKey($dbid))
                throw new KeePassPHPException("ID already exists.");

            // check that the database being added can be opened
            $db = self::openDatabase($dbContent, $dbPwd, $dbKeyContent);
            // add it to the db manager
            $dbHash = self::$_databaseManager->addWithKey(random_bytes(32),
                $dbContent, self::EXT_KDBX, true, true);
            if ($dbHash == null)
                throw new KeePassPHPException("Database file writing failed.");

            // try to add the key file if it exists
            if (!empty($dbKeyContent)) {
                $keyFileHash = self::$_keyManager->addWithKey(random_bytes(32),
                    $dbKeyContent, self::PREFEXT_KEY, true, true);
                if ($keyFileHash == null)
                    throw new KeePassPHPException("Key file writing failed.");
            }

            // build the KphpDB instance
            $kphpdb = $cache
                ? KphpDB::createFromDatabase($db, $dbHash, $keyFileHash)
                : KphpDB::createEmpty($dbHash, $keyFileHash);
            $error = null;
            $kphpdbContent = $kphpdb->toKdbx(
                new KeyFromPassword($kphpdbPwd, KdbxFile::HASH),
                $filter, $error);
            if ($kphpdbContent == null)
                throw new KeePassPHPException($error);

            // add the KphpDB instance
            $dbidHash = self::$_kphpdbManager->addWithKey($dbid,
                $kphpdbContent, self::EXT_KDBX, true, true);
            if ($dbidHash == null)
                throw new KeePassPHPException("KphpDB file writing failed.");
            return true;
        } catch (KeePassPHPException $exception) {
            if ($dbHash != null) {
                if (!self::$_databaseManager->remove($dbHash))
                    self::addDebug("Cannot delete database '" . $dbHash . "'.");
            }
            if ($keyFileHash != null) {
                if (!self::$_keyManager->remove($keyFileHash))
                    self::addDebug("Cannot delete key file '" .
                        $keyFileHash . "'.");
            }
            self::raiseError($exception);
            return false;
        }
    }

    /**
     * Get the database filename from the $dbid.
     * @param string $dbid A database ID.
     * @param string $kphpdbPwd The password of the KphpDB file.
     * @return string|boolean the filename of database if the database $dbid existed,
     *         false otherwise.
     * @throws Exception
     */
    public static function getDatabaseFilename($dbid, $kphpdbPwd)
    {
        if (!self::$_started) {
            self::addDebug("KeepassPHP is not started!");
            return false;
        }

        try {
            $kphpdb = self::openKphpDB($dbid, $kphpdbPwd);
            $hash = $kphpdb->getDBFileHash();
            if ($hash !== null) {
                $path = 'keepassphp'
                    . DIRECTORY_SEPARATOR
                    . rtrim(self::DEFAULT_DATA_DIR, DIRECTORY_SEPARATOR)
                    . DIRECTORY_SEPARATOR
                    . rtrim(self::DIR_DATABASE, DIRECTORY_SEPARATOR);

                $filename = (self::PREFIX_DATABASE) . '_' . $hash . '.' . (self::EXT_KDBX);

                return $path . DIRECTORY_SEPARATOR . $filename;
            }
        } catch (KeePassPHPException $exception) {
            self::raiseError($exception);
            return false;
        }
        return false;
    }

    /**
     * Removes the database of id $dbid from the internal KeePassPHP database.
     * @param string $dbid A database ID.
     * @param KphpDB $kphpdbPwd The password of the KphpDB file.
     * @return boolean true if the database $dbid existed and could be removed,
     *         false otherwise.
     * @throws Exception
     */
    public static function removeDatabase($dbid, $kphpdbPwd)
    {
        if (!self::$_started) {
            self::addDebug("KeepassPHP is not started!");
            return false;
        }

        try {
            $kphpdb = self::openKphpDB($dbid, $kphpdbPwd);
            $hash = $kphpdb->getDBFileHash();
            if ($hash !== null) {
                if (!self::$_databaseManager->remove($hash))
                    self::addDebug("Cannot delete database '" . $hash . "'.");
            }
            $hash = $kphpdb->getKeyFileHash();
            if ($hash !== null) {
                if (!self::$_keyManager->remove($hash))
                    self::addDebug("Cannot delete key file '" . $hash . "'.");
            }
            return self::$_kphpdbManager->removeFromKey($dbid);
        } catch (KeePassPHPException $exception) {
            self::raiseError($exception);
            return false;
        }
    }

    /**
     * Checks whether a database of id $dbid exists in the internal KeePassPHP
     * database.
     * @param string $dbid A database ID.
     * @return boolean true if $dbid exists, false otherwise.
     * @throws Exception
     */
    public static function existsKphpDB($dbid)
    {
        if (!self::$_started) {
            self::addDebug("KeepassPHP is not started!");
            return false;
        }
        return self::$_kphpdbManager->existsKey($dbid);
    }

    /**
     * Checks whether the internal KeePassPHP password for the id $dbid is
     * $kphpdbPwd.
     * @param string $dbid A database ID.
     * @param KphpDB $kphpdbPwd The password of the KphpDB file.
     * @return boolean true $kphpdbPwd is the password for the id $dbid.
     * @throws Exception
     */
    public static function checkKphpDBPassword($dbid, $kphpdbPwd)
    {
        if (!self::$_started) {
            self::addDebug("KeepassPHP is not started!");
            return false;
        }
        try {
            self::openKphpDB($dbid, $kphpdbPwd);
            return true;
        } catch (KeePassPHPException $e) {
            self::raiseError($e);
            return false;
        }
    }


    /***************************
     * Low-level API shortcuts *
     ***************************/

    /**
     * Creates a KeePass master key.
     * @return CompositeKey A new CompositeKey instance.
     */
    public static function masterKey()
    {
        return new CompositeKey(KdbxFile::HASH);
    }

    /**
     * Creates a key from a password.
     * @param string $pwd A text password.
     * @return KeyFromPassword new KeyFromPassword instance.
     */
    public static function keyFromPassword($pwd)
    {
        return new KeyFromPassword($pwd, KdbxFile::HASH);
    }

    /**
     * Adds a password to a master key.
     * @param CompositeKey $mkey A master key.
     * @param string $pwd A text password.
     * @return boolean true if the operation succeeded, false otherwise.
     */
    public static function addPassword(CompositeKey $mkey, $pwd)
    {
        $mkey->addKey(self::keyFromPassword($pwd));
        return true;
    }

    /**
     * Adds a file key to a master key.
     * @param string $mkey A master key.
     * @param string $file The path of a file key.
     * @return boolean true if the operation succeeded, false otherwise.
     */
    public static function addKeyFile(CompositeKey $mkey, $file)
    {
        if (empty($file))
            return true;
        $k = new KeyFromFile(file_get_contents($file));
        if (!$k->isParsed)
            return false;
        $mkey->addKey($k);
        return true;
    }

    /**
     * Opens a KeePass password database (.kdbx) file with the key $mkey.
     * @param string $file The path of a KeePass password database file.
     * @param IKey $mkey A master key.
     * @param string &$error A string that will receive a message in case of error.
     * @return Database A new Database instance, or null in case of error.
     */
    public static function openDatabaseFile($file, IKey $mkey, &$error)
    {
        $reader = ResourceReader::openFile($file);
        if ($reader == null) {
            $error = "file '" . $file . '" does not exist.';
            return null;
        }
        $db = Database::loadFromKdbx($reader, $mkey, $error);
        $reader->close();
        return $db;
    }

    /**
     * Embedds a string into a new kdbx file with the key $key, using $rounds
     * rounds of encryption. Use the method decryptFromKdbx() on the result
     * with the same key to get back $content from the kdbx file.
     * @param string $content A string that will be embedded.
     * @param IKey $key An IKey instance.
     * @param integer $rounds An integer.
     * @param string &$error A string that will receive a message in case of error.
     * @return string
     * @throws Exception
     */
    public static function encryptInKdbx($content, IKey $key, $rounds, &$error)
    {
        $kdbx = KdbxFile::createForEncrypting($rounds, $error);
        if ($kdbx == null)
            return null;
        print_r($kdbx->getHeaderHash());
        return $kdbx->encrypt($kdbx->getHeaderHash() . $content, $key, $error);
    }

    /**
     * Extracts a string embedded in a kdbx file, decrypting it with the key
     * $key.
     * @param string $content The content of the kdbx file, as a string.
     * @param IKey $key An IKey instance.
     * @param boolean $headerHash true if the header hash is prepended to the decrypted
     *                    content (use true if the kdbx file was created with
     *                    the metod encryptInKdbx()).
     * @param string &$error A string that will receive a message in case of error.
     * @return Database A new Database instance decrypted embedded string, or null in case of error.
     */
    public static function decryptFromKdbx($content, IKey $key, $headerHash,
                                           &$error)
    {
        $reader = new StringReader($content);
        $result = KdbxFile::decrypt($reader, $key, $error);
        $reader->close();
        if ($result === null)
            return null;
        $content = $result->getContent();
        if ($headerHash) {
            $hash = $result->getHeaderHash();
            $hashLen = strlen($hash);
            if (strlen($content) < $hashLen ||
                substr($content, 0, $hashLen) != $hash) {
                $error = "Kdbx file decrypt: header hash is not correct.";
                return null;
            }
            $content = substr($content, $hashLen);
        }

        print_r($content);
        die;

        $db = Database::loadFromXML($content, $result->getRandomStream(), $error);
        if ($db == null) throw new KeePassPHPException($error);
        return $db;
    }

    /*********************
     * private functions *
     *********************/

    /**
     * Opens the database $dbContent with the keys $dbPwd and $dbKeyContent.
     * @param string $dbContent The content of a KeePass database file.
     * @param string $dbPwd A text password for the database file.
     * @param string $dbKeyContent A possible key file for the database file.
     * @return Database A non-null Database instance.
     * @throws KeePassPHPException
     */
    private static function openDatabase($dbContent, $dbPwd, $dbKeyContent)
    {
        $ckey = new CompositeKey(KdbxFile::HASH);
        $ckey->addKey(new KeyFromPassword($dbPwd, KdbxFile::HASH));
        if (!empty($dbKeyContent)) {
            $fileKey = new KeyFromFile($dbKeyContent);
            if (!$fileKey->isParsed)
                throw new KeePassPHPException("key file parsing failure");
            $ckey->addKey($fileKey);
        }

        $error = null;
        $reader = new StringReader($dbContent);
        $db = Database::loadFromKdbx($reader, $ckey, $error);
        $reader->close();
        if ($db == null)
            throw new KeePassPHPException($error);
        return $db;
    }

    /**
     * Opens the KphpDB file of id $dbid with the password $kphpdbPwd.
     * @param String $dbid A database ID.
     * @param string $kphpdbPwd The password of the KphpDB file.
     * @return KphpDB A non-null KpbpDB instance.
     * @throws KeePassPHPException
     * @throws Exception
     */
    private static function openKphpDB($dbid, $kphpdbPwd)
    {
        $kphpdbFile = self::$_kphpdbManager->getContentFromKey($dbid);
        if ($kphpdbFile == null)
            throw new KeePassPHPException(
                "KphpDB file not found or void (ID = " . $dbid . ").");
        $error = null;
        $reader = new StringReader($kphpdbFile);
        $kphpdb = KphpDB::loadFromKdbx($reader,
            new KeyFromPassword($kphpdbPwd, KdbxFile::HASH), $error);
        $reader->close();
        if ($kphpdb == null)
            throw new KeePassPHPException($error);
        return $kphpdb;
    }

    public static function createUUID($hashcode)
    {
        $l = 31;
        $better_token = md5(uniqid(rand(), true) . $hashcode);
        $rem = strlen($better_token)-$l;
        $unique_code = substr($better_token, 0, -$rem);
        return base64_encode(pack("h*", $unique_code));
    }

    public static function formatXML($xml)
    {
        $dom = new DOMDocument;
        $dom->preserveWhiteSpace = FALSE;
        $dom->loadXML($xml);
        $dom->formatOutput = TRUE;

        return $dom->saveXml();
    }
}
