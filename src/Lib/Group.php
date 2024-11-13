<?php

namespace KeePassPHP\Lib;

use DOMDocument;
use KeePassPHP\Filters\IFilter;
use KeePassPHP\Util\String\IBoxedString;
use KeePassPHP\Util\String\ProtectedString;

/**
 * A class that manages a group of a KeePass 2.x password database.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class Group
{
    /**
     * uuid of this group in base64.
     * @var string
     */
    public $uuid;
    /**
     * Name of the group (if non null).
     * @var string
     */
    public $name;
    /**
     * ID of the KeePass icon of this group (if non null).
     * @var string|null
     */
    public $icon;
    /**
     * uuid in base64 of the custom icon of this group (if non null).
     * @var array[string]string
     */
    public $customIcon;
    /**
     * Array of sub-groups of this group (if non null).
     * @var Group[]
     */
    public $groups;
    /**
     * Array of entries of this group (if non null).
     * @var Entry[]
     */
    public $entries;
    /**
     * Complete Array of sub-groups of this group (if non null).
     * @var Group[]
     */
    public $complete_group = array();

    private function __construct()
    {
        $this->uuid = null;
        $this->name = null;
        $this->icon = null;
        $this->customIcon = null;
        $this->groups = null;
        $this->entries = null;
    }

    /**
     * Gets the password of the entry of this group or of a sub-group whose
     * uuid is $uuid.
     * @param $uuid string An entry uuid in base64.
     * @return IBoxedString|null The decrypted password if the entry exists inside this group or
     *         a sub-group, null otherwise.
     */
    public function getPassword($uuid)
    {
        if ($this->entries != null) {
            foreach ($this->entries as &$entry) {
                if ($entry->uuid === $uuid)
                    return $entry->password;
            }
        }
        if ($this->groups != null) {
            foreach ($this->groups as &$group) {
                $value = $group->getPassword($uuid);
                if ($value != null)
                    return $value;
            }
        }
        return null;
    }

    public function setPassword($uuid, $pass)
    {
        if ($this->entries != null) {
            foreach ($this->entries as &$entry) {
                if ($entry->uuid === $uuid) {
                    $entry->password = new ProtectedString($pass, base64_encode($pass));
                    return true;
                }
            }
        }
        if ($this->groups != null) {
            foreach ($this->groups as &$group) {
                $value = $group->setPassword($uuid, $pass);
                if ($value != null)
                    return $value;
            }
        }
        return false;
    }

    /**
     * Gets the string field value of the entry of this group or of a sub-group
     * whose uuid is $uuid.
     * @param $uuid string An entry uuid in base64.
     * @param $key string A key.
     * @return string A string containing the value of the field if the entry if
     *         exists inside this group or a sub-group,
     *         an empty string if the entry exists but the string field,
     *         null if entry does not exists.
     */
    public function getStringField($uuid, $key)
    {
        if ($this->entries != null) {
            foreach ($this->entries as &$entry) {
                if ($entry->uuid === $uuid)
                    return $entry->getStringField($key);
            }
        }
        if ($this->groups != null) {
            foreach ($this->groups as &$group) {
                $value = $group->getStringField($uuid, $key);
                if ($value != null)
                    return $value;
            }
        }
        return null;
    }

    /**
     * List custom string fields of the entry of this group or of a sub-group
     * whose uuid is $uuid.
     * @param $uuid string An entry uuid in base64.
     * @return string[] A list of custom fields if the entry exists inside this group
     *         or a sub-group, null if entry does not exists.
     */
    public function listCustomFields($uuid)
    {
        if ($this->entries != null) {
            foreach ($this->entries as &$entry) {
                if ($entry->uuid === $uuid) {
                    return $entry->listCustomFields();
                }
            }
        }
        if ($this->groups != null) {
            foreach ($this->groups as &$group) {
                $value = $group->listCustomFields($uuid);
                if ($value !== null) /* strict compare */
                    return $value;
            }
        }
        return null;
    }

    /**
     * Adds a Group instance as a sub-group of this group.
     * @param $group Group A Group instance, possibly null (it is then ignored).
     */
    private function addGroup($group)
    {
        if ($group != null) {
            if ($this->groups == null)
                $this->groups = array();
            $this->groups[] = $group;
        }
    }

    /**
     * Adds an Entry instance to this group.
     * @param $entry Entry An Entry instance, possibly null (it is then ignored).
     */
    private function addEntry($entry)
    {
        if ($entry != null) {
            if ($this->entries == null)
                $this->entries = array();
            $this->entries[] = $entry;
        }
    }

    /**
     * Creates an array describing this group (with respect to the filter).
     * This array can be safely serialized to json after.
     * @param $filter IFilter A filter to select the data that is actually copied to
     *                the array.
     * @return array[string] An array containing this group.
     */
    public function toArray(IFilter $filter)
    {
        $result = array();
        if ($this->uuid != null)
            $result[Database::XML_UUID] = $this->uuid;
        if ($this->name != null)
            $result[Database::XML_NAME] = $this->name;
        if ($this->icon != null && $filter->acceptIcons())
            $result[Database::XML_ICONID] = $this->icon;
        if ($this->customIcon != null && $filter->acceptIcons())
            $result[Database::XML_CUSTOMICONUUID] = $this->customIcon;
        if ($this->groups != null) {
            $groups = array();
            foreach ($this->groups as &$group) {
                if ($filter->acceptGroup($group))
                    $groups[] = $group->toArray($filter);
            }
            if (!empty($groups))
                $result[Database::GROUPS] = $groups;
        }
        if ($this->entries != null) {
            $entries = array();
            foreach ($this->entries as &$entry) {
                if ($filter->acceptEntry($entry))
                    $entries[] = $entry->toArray($filter);
            }
            if (!empty($entries))
                $result[Database::ENTRIES] = $entries;
        }
        return $result;
    }

    public static function toXML(array $content)
    {

        $data = null;

        foreach ($content as $key => $value) {
            if(is_int($key)) $data .= "<Group>" . Group::toXML($value) . "</Group>";
            elseif($key === 'Times') {
                $data .= "<Times>";
                foreach ($value as $key_times => $value_times) {
                    $data .= "\n<{$key_times}>{$value_times}</{$key_times}>";
                }
                $data .= "</Times>";
            }
            elseif($key === 'Group') $data .= Group::toXML($value);
            elseif($key === 'Entry') $data .= Entry::toXML($value);
            else
                $data .= "<{$key}>{$value}</{$key}>";
        }

        return $data;
    }

    /**
     * Creates a new Group instance from an array created by the method
     * toArray() of another Group instance.
     * @param $array array[string] An array created by the method toArray().
     * @param $version int The version of the array format.
     * @return Group A Group instance if the parsing went okay, null otherwise.
     */
    public static function loadFromArray(array $array, $version)
    {
        if ($array == null)
            return null;
        $group = new Group();
        $group->uuid = Database::getIfSet($array, Database::XML_UUID);
        $group->name = Database::getIfSet($array, Database::XML_NAME);
        $group->icon = Database::getIfSet($array, Database::XML_ICONID);
        $group->customIcon = Database::getIfSet($array, Database::XML_CUSTOMICONUUID);
        $groups = Database::getIfSet($array, Database::GROUPS);
        if (!empty($groups)) {
            foreach ($groups as &$subgroup)
                $group->addGroup(self::loadFromArray($subgroup, $version));
        }
        $entries = Database::getIfSet($array, Database::ENTRIES);
        if (!empty($entries)) {
            foreach ($entries as &$entry)
                $group->addEntry(Entry::loadFromArray($entry, $version));
        }
        return $group;
    }

    /**
     * Creates a new Group instance from a ProtectedXMLReader instance reading
     * a KeePass 2.x database and located at a Group element node.
     * @param $reader ProtectedXMLReader A XML reader.
     * @param Database|null $context The database being built, for context
     * @param Bool $basic_view A bool define view mode of data xml processing.
     */
    public static function loadFromXML(ProtectedXMLReader $reader, Database $context = null, $basic_view = true)
    {
        if ($reader == null) return null;
        $group = new Group();
        $d = $reader->depth();
        while ($reader->read($d)) {
            if($basic_view) {
                if ($reader->isElement(Database::XML_GROUP))
                    $group->addGroup(Group::loadFromXML($reader, $context));
                elseif ($reader->isElement(Database::XML_ENTRY))
                    $group->addEntry(Entry::loadFromXML($reader, $context));
                elseif ($reader->isElement(Database::XML_UUID))
                    $group->uuid = $reader->readTextInside();
                elseif ($reader->isElement(Database::XML_NAME))
                    $group->name = $reader->readTextInside();
                elseif ($reader->isElement(Database::XML_ICONID))
                    $group->icon = $reader->readTextInside();
                elseif ($reader->isElement(Database::XML_CUSTOMICONUUID))
                    $group->customIcon = $reader->readTextInside();
            } else {
                if ($reader->isElement(Database::XML_GROUP))
                    $group->complete_group['Group'][] = Group::loadFromXML($reader, $context, $basic_view);
                elseif ($reader->isElement(Database::XML_ENTRY))
                    $group->complete_group['Entry'][] = Entry::loadFromXML($reader, $context, $basic_view);
                elseif ($reader->isElement('Times')) {
                    $times = $reader->depth();
                    while ($reader->read($times)) {
                        $group->complete_group['Times'][$reader->elementName()] = $reader->readTextInside() ?: '';
                    }
                }
                else
                    $group->complete_group[$reader->elementName()] = $reader->readTextInside();
            }
        }
        return $basic_view ? $group : $group->complete_group;
    }

    public static function loadToXML(ProtectedXMLReader $reader, Database $context = null)
    {

    }
}
