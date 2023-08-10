<?php


namespace KeePassPHP\Util\Stream;


/**
 * An object that can randomly generate bytes.
 */
interface IRandomStream
{
    /**
     * Generates $n random bytes and returns them as a string.
     * @param int $n The number of bytes to generate.
     * @return string A $n-long string.
     */
    public function getNextBytes($n);
}

