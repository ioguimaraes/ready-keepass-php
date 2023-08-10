<?php


namespace KeePassPHP\Lib;


class BinaryRef
{
    private $source;
    private $name;

    /**
     * BinaryRef constructor.
     * @param Binary $source
     */
    private function __construct(Binary $source)
    {
        $this->source = $source;
    }

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->name ?: $this->source->getId();
    }

    /**
     * @param mixed $name
     */
    public function setName($name)
    {
        $this->name = $name;
    }

    /**
     * @return Binary
     */
    public function getSource()
    {
        return $this->source;
    }

    public function __call($name, $arguments)
    {
        //Whatever you say
        return call_user_func_array(array($this->getSource(), $name), $arguments);
    }

    /**
     * Gets the binary instance with the ID specifeid
     * @param Database $context The context in which to search
     * @param string|int $ref The ref/ID to search for
     * @return BinaryRef|null The reference or null
     */
    public static function resolve(Database $context, $ref)
    {
        $value = null;
        //Resolve the binary against the database
        $existingBinaries = $context->getBinaries();
        if (is_array($existingBinaries)) {
            //Find the binary
            foreach ($existingBinaries as $existingBinary) {
                //If the ID matches the ref
                if ($existingBinaries && $existingBinary->getId() == $ref) {
                    //Copy this one
                    $value = $existingBinary;
                    //Stop searching
                    break;
                }
            }
        }
        //
        return $value != null ? new BinaryRef($value) : null;
    }
}