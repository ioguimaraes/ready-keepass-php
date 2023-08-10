<?php


namespace KeePassPHP\Key;


/**
 * An object that contains a secret in the form of a hash.
 */
interface IKey
{
    /**
     * Gets this instance hash.
     * @return string A raw hash string.
     */
    public function getHash();
}

