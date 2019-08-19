<?php

namespace HttpSignatures;

class Context
{
    /** @var array */
    private $headers;

    /** @var KeyStoreInterface */
    private $keyStore;

    /** @var array */
    private $keys;

    /** @var string */
    private $signingKeyId;

    /** @var string */
    private $hashAlgorithm;

    /** @var string */
    private $defaultCreated = 'now';

    /** @var string */
    private $defaultExpires = 'none';

    /**
     * @param array $args
     *
     * @throws Exception
     */
    public function __construct($args = [])
    {
        if (isset($args['keys']) && isset($args['keyStore'])) {
            throw new Exception(__CLASS__.' accepts keys or keyStore but not both');
        } elseif (isset($args['keys'])) {
            // array of keyId => keySecret
            $this->keys = $args['keys'];
        } elseif (isset($args['keyStore'])) {
            $this->setKeyStore($args['keyStore']);
        }

        // algorithm for signing; not necessary for verifying.
        if (isset($args['algorithm'])) {
            $this->setAlgorithm($args['algorithm']);
        } else {
            $this->setAlgorithm('hs2019');
        }

        // TODO: Read headers as minimum for verification
        // TODO: Function to set headers after creation
        // headers list for signing; not necessary for verifying.
        if (isset($args['headers'])) {
            $this->headers = $args['headers'];
        }

        // signingKeyId specifies the key used for signing messages.
        if (isset($args['signingKeyId'])) {
            $this->signingKeyId = $args['signingKeyId'];
        } elseif (isset($args['keys']) && 1 === count($args['keys'])) {
            list($this->signingKeyId) = array_keys($args['keys']); // first key
        }
    }

    public function sign($message)
    {
        return $this->signer()->sign($message);
    }

    public function authorize($message)
    {
        return $this->signer()->authorize($message);
    }

    /**
     * @return Signer
     *
     * @throws Exception
     */
    public function signer()
    {
        try {
            $signingKey = $this->signingKey();
        } catch (ContextException $e) {
            throw $e;
        }
        if (empty($this->hashAlgorithm)) {
            $hashAlgorithm = 'hs2019';
        } else {
            $hashAlgorithm = $this->hashAlgorithm;
        }
        if (empty($this->signatureAlgorithm)) {
            $signatureAlgorithm = $signingKey->getType();
        } else {
            $signatureAlgorithm = $this->signatureAlgorithm;
        }
        $signingKeyType = $signingKey->getType();
        if ($signingKeyType != $signatureAlgorithm) {
            throw new ContextException(
              "Signature algorithm '$this->signatureAlgorithm' cannot be ".
              "used with signing key type '$signingKeyType'", 1);
        }
        switch ($signingKeyType) {
            case 'rsa':
              $algorithm = new RsaAlgorithm($hashAlgorithm);
              break;
            case 'dsa':
              $algorithm = new DsaAlgorithm($hashAlgorithm);
              break;
            case 'hmac':
              $algorithm = new HmacAlgorithm($hashAlgorithm);
              break;
            case 'ec':
              $algorithm = new EcAlgorithm($hashAlgorithm);
              break;

            default:
              throw new ContextException(
                "Unrecognised '$signingKeyType'", 1);
              break;
          }

        return new Signer(
            $this->signingKey(),
            $algorithm,
            $this->headerList(),
            $this->signatureDates()
      );
    }

    /**
     * @return Verifier
     */
    public function verifier()
    {
        return new Verifier($this->keyStore());
    }

    /**
     * @return Key
     *
     * @throws Exception
     * @throws KeyStoreException
     */
    private function signingKey()
    {
        if (empty($this->signingKeyId) && 1 == $this->keyStore()->count()) {
            $this->signingKeyId = $this->keyStore()->fetch()->getId();
        }
        if (isset($this->signingKeyId)) {
            return $this->keyStore()->fetch($this->signingKeyId);
        } else {
            throw new ContextException('No implicit or specified signing key');
        }
    }

    /**
     * @return HeaderList
     */
    private function headerList()
    {
        if (!is_null($this->headers)) {
            return new HeaderList($this->headers, true);
        } else {
            if (in_array($this->hashAlgorithm, ['hs2019'])) {
                return new HeaderList(['(created)'], false);
            } else {
                return new HeaderList(['date'], false);
            }
        }
    }

    /**
     * @return KeyStore
     */
    private function keyStore()
    {
        if (empty($this->keyStore)) {
            $this->keyStore = new KeyStore($this->keys);
        }

        return $this->keyStore;
    }

    /**
     * @param KeyStoreInterface $keyStore
     */
    private function setKeyStore(KeyStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    public function setAlgorithm($name)
    {
        $algorithm = explode('-', $name);
        if (in_array($name, ['hs2019'])) {
            $this->hashAlgorithm = $name;
        } elseif (sizeof($algorithm) < 2) {
            throw new ContextException(
              "Unrecognised algorithm: '$name'", 1);
        } else {
            switch ($algorithm[0]) {
              case 'ec':
              case 'rsa':
              case 'dsa':
              case 'hmac':
                $this->signatureAlgorithm = $algorithm[0];
                break;

              default:
                throw new AlgorithmException(
                  "Unrecognised signature algorithm: '$algorithm[0]'", 1);
                break;
            }
            switch ($algorithm[1]) {
              case 'sha1':
              case 'sha256':
              case 'sha384':
              case 'sha512':
                $this->hashAlgorithm = $algorithm[1];
                break;

              default:
                throw new AlgorithmException(
                  "Unrecognised hash algorithm: '$algorithm[1]'", 1);
                break;
            }
        }
    }

    private function algorithm()
    {
        if (empty($this->algorithm)) {
            return false;
        } else {
            return $this->algorithm;
        }
    }

    public function addKeys($value)
    {
        if (empty($this->keyStore)) {
            $this->keyStore = new KeyStore($this->keys);
        }

        $this->keyStore->addKeys($value);
    }

    public function setCreated($created)
    {
        $this->defaultCreated = $created;
    }

    public function setExpires($expires)
    {
        $this->defaultexpires = $expires;
    }

    public function signatureDates()
    {
        $signatureDates = new SignatureDates();
        $signatureDates->setCreated(SignatureDates::Offset($this->defaultCreated));
        $signatureDates->setExpires(SignatureDates::Offset($this->defaultExpires));

        return $signatureDates;
    }
}
