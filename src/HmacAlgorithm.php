<?php

namespace HttpSignatures;

class HmacAlgorithm implements AlgorithmInterface
{
    /** @var string */
    private $digestName;

    /**
     * @param string $digestName
     */
    public function __construct($digestName)
    {
        if (in_array($digestName, ['sha1', 'sha256', 'sha384', 'sha512', 'hs2019'])) {
            $this->digestName = $digestName;
        } else {
            throw new AlgorithmException($digestName.' is not a supported hash format');
        }
    }

    /**
     * @return string
     */
    public function name()
    {
        if (in_array($this->digestName, ['hs2019'])) {
            return $this->digestName;
        } else {
            return 'hmac-'.$this->digestName;
        }
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public function sign($secret, $data)
    {
        return hash_hmac($this->digestName, $data, $secret, true);
    }
}
