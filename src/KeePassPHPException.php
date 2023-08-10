<?php


namespace KeePassPHP;


use Exception;

class KeePassPHPException extends Exception
{
    public function __construct($message)
    {
        parent::__construct($message);
    }
}
