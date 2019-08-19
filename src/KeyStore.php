<?php

namespace HttpSignatures;

class KeyStore implements KeyStoreInterface
{
    /** @var Key[] */
    private $keys;

    /**
     * @param array $keys
     */
    public function __construct($keys = [])
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
    public function fetch($keyId = null)
    {
        if (empty($keyId) && 1 == sizeof($this->keys)) {
            return reset($this->keys);
        }
        if (isset($this->keys[$keyId])) {
            return $this->keys[$keyId];
        } else {
            throw new KeyStoreException("Key '$keyId' not found");
        }
    }

    public function count()
    {
        return sizeof($this->keys);
    }

    public function addKeys($keys)
    {
        $newKeys = [];
        foreach ($keys as $id => $key) {
            if (isset($this->keys[$id])) {
                throw new KeyStoreException(
                "keyId '$id' already in Key Store", 1
              );
            } else {
                $newKeys[$id] = new Key($id, $key);
            }
        }
        $this->keys = array_merge($newKeys, $this->keys);
    }
}
