<?php

namespace KeePassPHP\Util\String;

/**
 * A boxed plain string.
 */
class UnprotectedString implements IBoxedString
{
    private $_string;

    public function __construct($string)
    {
        $this->_string = $string;
    }

    /**
     * Gets the boxed string.
     * @return string a string.
     */
    public function getPlainString()
    {
        return $this->_string;
    }
}