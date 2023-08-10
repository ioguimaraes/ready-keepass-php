<?php


namespace KeePassPHP\Key;


/**
 * An IKey built from a string password.
 */
class KeyFromPassword extends KeyFromHash
{
    /**
     * Constructs a KeyFromPassword instance from the password $pwd.
     * @param string $pwd A string.
     * @param string $hashAlgo A hash algorithm name.
     */
    public function __construct($pwd, $hashAlgo)
    {
        parent::__construct(hash($hashAlgo, $pwd, true));
    }
}