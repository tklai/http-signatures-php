<?php

namespace HttpSignatures;

class KeyStore implements KeyStoreInterface
{
    /** @var Key[] */
    private $keys;

    /**
     * @param array $keys
     */
    public function __construct($keys = null)
    {
        $this->keys = [];
        if (!empty($keys)) {
            foreach ($keys as $id => $key) {
                $this->keys[$id] = new Key($id, $key);
            }
        }
    }

    /**
     * @param string $keyId
     *
     * @return Key
     *
     * @throws KeyStoreException
     */
    public function fetch($keyId)
    {
        if (isset($this->keys[$keyId])) {
            return $this->keys[$keyId];
        } else {
            throw new KeyStoreException("Key '$keyId' not found");
        }
    }

    public function withKeys($keys)
    {
        foreach ($keys as $keyId => $value) {
            $this->keys[$keyId] = new Key($keyId, $value);
        }

        return $this;
    }

    public function getCount()
    {
        return sizeof($this->keys);
    }
}
