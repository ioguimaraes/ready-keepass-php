<?php


namespace KeePassPHP\Util\Reader;


/**
 * Implementation of Readers, id est objects that can read data on demand from
 * a source, in the fashion of a stream in C# or Java.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */

/**
 * Base class for all readers. Instances of this class can read bytes from a
 * source, which produces them one by one until no more can be produced. The
 * end of the stream may not be known in advance. The backing data source can
 * be a string, a file, a network resource, a transformation of another reader,
 * etc.
 */
abstract class Reader
{
    /**
     * Checks whether more bytes can be read from this instance.
     * @return true if more bytes can be read, false otherwise.
     */
    abstract public function canRead();

    /**
     * Tries to read $n bytes from this instance. This method will read as many
     * bytes as required, except if the underlying byte stream ends. It means
     * that if the result does not contain $n bytes, there is no need to call
     * this method again; this instance can no longer read new bytes.
     * @return string a string containing at most $n bytes, or null if no more bytes
     *         can be read.
     */
    abstract public function read($n);

    /**
     * Reads all remaining bytes from this instance.
     * @return string a string containing all remaining bytes that this Read can read,
     *         or null if no more bytes can be read.
     */
    abstract public function readToTheEnd();

    /**
     * Closes this instance, possibly dismissing the resources it was using.
     */
    abstract public function close();

    /**
     * Tries to read $n bytes from this instance, and return them as an
     * integer (in little-endian).
     * Note that depending on the platform, PHP may not be able to correctly
     * handle integers greater than 2**31.
     * @return integer at most $n bytes encoded into one integer, or 0 if no more
     *         bytes can be read.
     */
    public function readNumber($n)
    {
        $s = $this->read($n);
        $l = strlen($s);
        $r = 0;
        for ($i = 0; $i < $l; $i++)
            $r += ord($s[$i]) << (8 * $i);
        return $r;
    }

    /**
     * Tries to read one (1) byte from this instance, and return it as
     * an integer.
     * @return integer one read byte as an integer, or 0 if no more bytes can be read.
     */
    public function readByte()
    {
        $s = $this->read(1);
        return empty($s) ? 0 : ord($s[0]);
    }
}
