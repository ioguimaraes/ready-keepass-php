<?php


namespace KeePassPHP\Filters;

use KeePassPHP\Lib\Entry;
use KeePassPHP\Lib\Group;

/**
 * A default filter that writes everything except from passwords.
 */
class AllExceptFromPasswordsFilter implements IFilter
{
    public function acceptEntry(Entry $entry)
    {
        return true;
    }

    public function acceptGroup(Group $group)
    {
        return true;
    }

    public function acceptHistoryEntry(Entry $historyEntry)
    {
        return true;
    }

    public function acceptTags()
    {
        return true;
    }

    public function acceptIcons()
    {
        return true;
    }

    public function acceptPasswords()
    {
        return false;
    }

    public function acceptStrings($key)
    {
        return true;
    }
}
