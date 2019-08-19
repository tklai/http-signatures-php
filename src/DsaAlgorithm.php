<?php

namespace HttpSignatures;

class DsaAlgorithm implements AlgorithmInterface
{
    /** @var string */
    private $digestName;

    /**
     * @param string $digestName
     */
    public function __construct($digestName)
    {
        if (in_array($digestName, ['sha1', 'sha256', 'sha384', 'sha512'])) {
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
        return sprintf('dsa-%s', $this->digestName);
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     *
     * @throws \HttpSignatures\AlgorithmException
     */
    public function sign($signingKey, $data)
    {
        $algo = $this->getRsaHashAlgo($this->digestName);
        if (!openssl_get_privatekey($signingKey)) {
            throw new AlgorithmException("OpenSSL doesn't understand the supplied key (not valid or not found)");
        }
        $signature = '';
        openssl_sign($data, $signature, $signingKey, $algo);

        return $signature;
    }

    public function verify($message, $signature, $verifyingKey)
    {
        $algo = $this->getRsaHashAlgo($this->digestName);

        return 1 === openssl_verify($message, base64_decode($signature), $verifyingKey, $algo);
    }

    private function getRsaHashAlgo($digestName)
    {
        switch ($digestName) {
        case 'sha512':
            return OPENSSL_ALGO_SHA512;
        case 'sha384':
            return OPENSSL_ALGO_SHA384;
        case 'sha256':
            return OPENSSL_ALGO_SHA256;
        case 'sha1':
            return OPENSSL_ALGO_SHA1;
        default:
            throw new AlgorithmException($digestName.' is not a supported hash format');
      }
    }
}
