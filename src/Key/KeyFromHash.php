<?php

namespace KeePassPHP\Key;

/**
 * An IKey built from something already hashed.
 */
class KeyFromHash implements IKey
{
    protected $hash;

    /**
     * Stores the given hash string.
     * @param string $h A raw hash string.
     */
    public function __construct($h)
    {
        $this->hash = $h;
    }

    /**
     * Retrieves the stored hash.
     * @return string A raw hash string.
     */
    public function getHash()
    {
        return $this->hash;
    }
}