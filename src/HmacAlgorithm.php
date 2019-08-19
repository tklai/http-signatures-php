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
        switch ($this->digestName) {
          case 'hs2019':
          case 'sha512':
            $digest = 'sha512';
            break;
          case 'sha384':
            $digest = 'sha384';
            break;
          case 'sha256':
            $digest = 'sha256';
            break;
          case 'sha1':
            $digest = 'sha1';
            break;
          default:
            throw new AlgorithmException($digestName.' is not a supported hash format');
            break;
        }

        return hash_hmac($digest, $data, $secret, true);
    }
}
