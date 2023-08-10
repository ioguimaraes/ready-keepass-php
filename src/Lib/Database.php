<?php

namespace KeePassPHP\Lib;

use KeePassPHP\Filters\AllExceptFromPasswordsFilter;
use KeePassPHP\Filters\IFilter;
use KeePassPHP\Kdbx\KdbxFile;
use KeePassPHP\Key\IKey;
use KeePassPHP\Util\Reader\Reader;
use KeePassPHP\Util\Stream\IRandomStream;

/**
 * A class that manages a KeePass 2.x password database.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class Database
{
    const XML_KEEPASSFILE = "KeePassFile";
    const XML_META = "Meta";
    const XML_HEADERHASH = "HeaderHash";
    const XML_DATABASENAME = "DatabaseName";
    const XML_CUSTOMICONS = "CustomIcons";
    const XML_BINARIES = "Binaries";
    const XML_ICON = "Icon";
    const XML_UUID = "UUID";
    const XML_DATA = "Data";
    const XML_ROOT = "Root";
    const XML_BINARY = "Binary";
    const XML_GROUP = "Group";
    const XML_ENTRY = "Entry";
    const XML_NAME = "Name";
    const XML_ICONID = "IconID";
    const XML_CUSTOMICONUUID = "CustomIconUUID";
    const XML_STRING = "String";
    const XML_STRING_KEY = "Key";
    const XML_STRING_VALUE = "Value";
    const XML_HISTORY = "History";
    const XML_TAGS = "Tags";

    const KEY_PASSWORD = "Password";
    const KEY_STRINGFIELDS = "StringFields";
    const KEY_TITLE = "Title";
    const KEY_USERNAME = "UserName";
    const KEY_URL = "URL";
    const KEY_NOTES = "Notes";

    const GROUPS = "Groups";
    const ENTRIES = "Entries";

    /**
     * @var string
     */
    private $_name;
    /**
     * @var Group[]
     */
    private $_groups;
    /**
     * @var Binary[]
     */
    private $_binaries;
    /**
     * Associative array (icon uuid in base64 => icon data in base64) keeping
     * the data of all custom icons.
     * @var array[string]string
     */
    private $_customIcons;
    /**
     * Header hash registered in this database.
     * @var string
     */
    private $_headerHash;
    private $_contentXML;
    private $_randomStream;

    private function __construct()
    {
        $this->_name = null;
        $this->_groups = null;
        $this->_customIcons = null;
        $this->_headerHash = null;
    }

    /**
     * Gets the name of this database.
     * @return string This database name.
     */
    public function getName()
    {
        return $this->_name;
    }

    /**
     * Gets the groups of this database.
     * @return Group[] An array of Group instances.
     */
    public function getGroups()
    {
        return $this->_groups;
    }

    /**
     * @return Binary[]
     */
    public function getBinaries()
    {
        return $this->_binaries;
    }

    /**
     * Gets the data of the custom icon whose uuid is $uuid.
     * @param $uuid string A custom icon uuid in base64.
     * @return string|null A custom icon data in base64 if it exists, null otherwise.
     */
    public function getCustomIcon($uuid)
    {
        return $this->_customIcons == null ? null
            : "data:image/png;base64," . $this->_customIcons[$uuid];
    }

    /**
     * Gets the XML data of this database.
     * @return string|null A XML info instances.
     */
    public function getContentXML()
    {
        return $this->_contentXML;
    }

    /**
     * Gets the random stream data of this database.
     * @return string|null A random stream info instances.
     */
    public function getRandomStream()
    {
        return $this->_randomStream;
    }

    /**
     * Gets the password of the entry whose uuid is $uuid.
     * @param $uuid string An entry uuid in base64.
     * @return string The decrypted password if the entry exists, null otherwise.
     */
    public function getPassword($uuid)
    {
        if ($this->_groups != null) {
            foreach ($this->_groups as &$group) {
                $value = $group->getPassword($uuid);
//                echo "Teste database -----\r\n";
//                print_r($value);
//                die;
                if ($value != null)
                    return $value->getPlainString();
            }
        }
        return null;
    }

    /**
     * Gets the string field value of the entry whose uuid is $uuid.
     * @param $uuid string An entry uuid in base64.
     * @param $key string A key.
     * @return string|null A string of value the field if the entry if exists,
     *         an empty string if the entry exists but the string field,
     *         null if entry does not exists.
     */
    public function getStringField($uuid, $key)
    {
        if ($this->_groups != null) {
            foreach ($this->_groups as &$group) {
                $value = $group->getStringField($uuid, $key);
                if ($value != null)
                    return $value;
            }
        }
        return null;
    }

    /**
     * List custom string field variables of the entry whose uuid is $uuid.
     * @param $uuid string An entry uuid in base64.
     * @return string[] A list of custom fields if the entry exists,
     *         null if entry does not exists.
     */
    public function listCustomFields($uuid)
    {
        if ($this->_groups != null) {
            foreach ($this->_groups as &$group) {
                $value = $group->listCustomFields($uuid);
                if ($value !== null) /* strict compare */
                    return $value;
            }
        }
        return null;
    }

    /**
     * Parses a custom icon XML element node, and adds the result to the
     * $customIcons array.
     * @param $reader ProtectedXMLReader A ProtectedXMLReader instance located at a custom icon
     *                element node.
     */
    private function parseCustomIcon(ProtectedXMLReader $reader)
    {
        $uuid = null;
        $data = null;
        $d = $reader->depth();
        while ($reader->read($d)) {
            if ($reader->isElement(self::XML_UUID))
                $uuid = $reader->readTextInside();
            elseif ($reader->isElement(self::XML_DATA))
                $data = $reader->readTextInside();
        }
        if (!empty($uuid) && !empty($data)) {
            if ($this->_customIcons == null)
                $this->_customIcons = array();
            $this->_customIcons[$uuid] = $data;
        }
    }

    /**
     * Adds a Group instance to this Database.
     * @param Group $group A Group instance, possibly null (it is then ignored).
     */
    private function addGroup(Group $group)
    {
        if ($group != null) {
            if ($this->_groups == null)
                $this->_groups = array();
            $this->_groups[] = $group;
        }
    }

    /**
     * Adds a Binary instance to this Database.
     * @param Binary $binary A Binary instance, possibly null (it is then ignored).
     */
    private function addBinary(Binary $binary)
    {
        if ($binary != null) {
            if ($this->_binaries == null)
                $this->_binaries = array();
            array_push($this->_binaries, $binary);
        }
    }

    /**
     * Loads the content of a Database from a ProtectedXMLReader instance
     * reading a KeePass 2.x database and located at a KeePass file element
     * node.
     * @param $reader ProtectedXMLReader A XML reader.
     */
    private function parseXML(ProtectedXMLReader $reader)
    {
        $d = $reader->depth();
        while ($reader->read($d)) {
            if ($reader->isElement(self::XML_META)) {
                $metaD = $reader->depth();
                while ($reader->read($metaD)) {
                    if ($reader->isElement(self::XML_HEADERHASH))
                        $this->_headerHash = base64_decode($reader->readTextInside());
                    elseif ($reader->isElement(self::XML_DATABASENAME))
                        $this->_name = $reader->readTextInside();
                    elseif ($reader->isElement(self::XML_CUSTOMICONS)) {
                        $iconsD = $reader->depth();
                        while ($reader->read($iconsD)) {
                            if ($reader->isElement(self::XML_ICON))
                                $this->parseCustomIcon($reader);
                        }
                    } elseif ($reader->isElement(self::XML_BINARIES)) {
                        //Parse each Binary tag
                        $rootD = $reader->depth();
                        while ($reader->read($rootD)) {
                            if ($reader->isElement(self::XML_BINARY))
                                $this->addBinary(Binary::loadFromXML($reader, $this));
                        }
                    }
                }
            } elseif ($reader->isElement(self::XML_ROOT)) {
                $rootD = $reader->depth();
                while ($reader->read($rootD)) {
                    if ($reader->isElement(self::XML_GROUP))
                        $this->addGroup(Group::loadFromXML($reader, $this));
                }
            }
        }
    }

    /**
     * Creates an array describing this database (with respect to the filter).
     * This array can be safely serialized to json after.
     * @param IFilter $filter A filter to select the data that is actually copied to
     *                the array (if null, it will serialize everything except
     *                from passowrds).
     * @return array[string] An array containing this database (except passwords).
     */
    public function toArray(IFilter $filter = null)
    {
        if ($filter == null)
            $filter = new AllExceptFromPasswordsFilter();
        $result = array();
        if ($this->_name != null)
            $result[self::XML_DATABASENAME] = $this->_name;
        if ($this->_customIcons != null && $filter->acceptIcons())
            $result[self::XML_CUSTOMICONS] = $this->_customIcons;
        if ($this->_groups != null) {
            $groups = array();
            foreach ($this->_groups as &$group) {
                if ($filter->acceptGroup($group))
                    $groups[] = $group->toArray($filter);
            }
            if (!empty($groups))
                $result[self::GROUPS] = $groups;
        }
        return $result;
    }

    public function toXML(array $content, $xml, IRandomStream $randomStream, &$error)
    {

        $standard_file = file_get_contents(__DIR__ . "/../../standard.xml");

        $reader = new ProtectedXMLReader($randomStream);
        $reader->XML($xml);
        $reader->read(-1);
        $d = $reader->depth();
        while ($reader->read($d)) {
            if ($reader->isElement(self::XML_META)) {
                $metaD = $reader->depth();
                while ($reader->read($metaD)) {
                    $standard_file = str_replace("%%{$reader->elementName()}%%", $reader->readTextInside() ?: '', $standard_file);
                }
            }
            elseif ($reader->isElement(self::XML_ROOT)) {
                $rootD = $reader->depth();
                while ($reader->read($rootD)) {
                    if ($reader->isElement(self::XML_GROUP))
                        $this->addGroup(Group::loadFromXML($reader, $this));
                }
            }
        }
        print_r($standard_file);
        die;

        $error = null;
        return $xml;
    }

    /**
     * Creates a new Database instance from an array created by the method
     * toArray() of another Database instance.
     * @param $array array[string] An array created by the method toArray().
     * @param $version integer The version of the array format.
     * @param &$error string A string that will receive a message in case of error.
     * @return Database A Database instance if the parsing went okay, null otherwise.
     */
    public static function loadFromArray(array $array, $version, &$error)
    {
        if ($array == null) {
            $error = "Database array load: array is empty.";
            return null;
        }
        $db = new Database();
        $db->_name = self::getIfSet($array, self::XML_DATABASENAME);
        $db->_customIcons = self::getIfSet($array, self::XML_CUSTOMICONS);
        $groups = self::getIfSet($array, self::GROUPS);
        if (!empty($groups)) {
            foreach ($groups as &$group)
                $db->addGroup(Group::loadFromArray($group, $version));
        }
        if ($db->_name == null && $db->_groups == null) {
            $error = "Database array load: empty database.";
            return null;
        }
        $error = null;
        return $db;
    }

    /**
     * Creates a new Database instance from an XML string with the format of
     * a KeePass 2.x database.
     * @param $xml string An XML string.
     * @param $randomStream IRandomStream A IRandomStream instance to decrypt protected data.
     * @param &$error string A string that will receive a message in case of error.
     * @return Database A Database instance if the parsing went okay, null otherwise.
     */
    public static function loadFromXML($xml, IRandomStream $randomStream,
                                       &$error)
    {
        $reader = new ProtectedXMLReader($randomStream);
        if (!$reader->XML($xml) || !$reader->read(-1)) {
            $error = "Database XML load: cannot parse the XML string.";
            $reader->close();
            return null;
        }
        if (!$reader->isElement(self::XML_KEEPASSFILE)) {
            $error = "Database XML load: the root element is not '" . self::XML_KEEPASSFILE . "'.";
            $reader->close();
            return null;
        }
        $db = new Database();
        $db->_contentXML = $xml;
        $db->_randomStream = $randomStream;
        $db->parseXML($reader);
        $reader->close();
        if ($db->_name == null && $db->_groups == null) {
            $error = "Database XML load: empty database.";
            return null;
        }
        $error = null;
        return $db;
    }

    /**
     * Creates a new Database instance from a .kdbx (KeePass 2.x) file.
     * @param $reader Reader A Reader instance that reads a .kdbx file.
     * @param $key IKey A IKey instance to use to decrypt the .kdbx file.
     * @param &$error string A string that will receive a message in case of error.
     * @return Database A Database instance if the parsing went okay, null otherwise.
     */
    public static function loadFromKdbx(Reader $reader, IKey $key, &$error)
    {
        $kdbx = KdbxFile::decrypt($reader, $key, $error);
        if ($kdbx == null)
            return null;

        $db = self::loadFromXML($kdbx->getContent(), $kdbx->getRandomStream(),
            $error);
        if ($db == null)
            return null;
        if ($db->_headerHash !== $kdbx->getHeaderHash()) {
            $error = "Database Kdbx load: header hash is not correct.";
            return null;
        }
        return $db;
    }

    /**
     * Returns $array[$key] if it exists, null otherwise.
     * @param $array array An array.
     * @param $key string An array key.
     * @return mixed|null if it exists, null otherwise.
     */
    public static function getIfSet(array $array, $key)
    {
        return isset($array[$key]) ? $array[$key] : null;
    }

}
