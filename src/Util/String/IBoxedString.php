<?php


namespace KeePassPHP\Util\String;


/**
 * Implementation of protected strings, id est strings that may be stored in a
 * different form in memory, and whose real value is computed on demand.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */

/**
 * An object that can yield a string.
 */
interface IBoxedString
{
    /**
     * Gets the boxed string.
     * @return string a string.
     */
    public function getPlainString();
}

