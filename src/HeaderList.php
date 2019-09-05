<?php

namespace HttpSignatures;

class HeaderList
{
    /** @var array */
    public $names;

    /** @var bool */
    private $headerListSpecified;

    /**
     * @param array $names
     */
    public function __construct(array $names, $headerListSpecified = true)
    {
        $this->names = [];
        if (!$names) {
            $this->headerListSpecified = false;
        } else {
            foreach ($names as $name) {
                $this->names[] = strtolower($name);
            }
            $this->headerListSpecified = $headerListSpecified;
        }
    }

    /**
     * @param $string
     *
     * @return HeaderList
     */
    public static function fromString($string)
    {
        return new static(explode(' ', $string));
    }

    /**
     * @return string
     */
    public function string()
    {
        if (sizeof($this->names)) {
            return implode(' ', $this->names);
        } else {
            return '';
        }
    }

    /**
     * @return bool
     */
    public function headerListSpecified()
    {
        return $this->headerListSpecified;
    }

    /**
     * @param $name
     *
     * @return string
     */
    private function normalize($name)
    {
        return strtolower($name);
    }

    public function listHeaders()
    {
        return $this->names;
    }
}
