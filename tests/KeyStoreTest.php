<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use PHPUnit\Framework\TestCase;

class KeyStoreTest extends TestCase
{
    public function testKeyStore()
    {
        $ks = new KeyStore(['testkey' => 'abc123']);
        $this->assertEquals(
          'abc123',
          $ks->fetch('testkey')->getSigningKey()
        );
        $this->assertEquals(
          'secret',
          $ks->fetch('testkey')->getType()
        );
        $ks = $ks->withKeys([
          'testkey2' => 'def456',
          'testkey3' => 'foo-bar',
        ]);
        $this->assertEquals(
          3,
          $ks->getCount()
        );
        $this->assertEquals(
          'abc123',
          $ks->fetch('testkey')->getSigningKey()
        );
        $this->assertEquals(
          'secret',
          $ks->fetch('testkey2')->getType()
        );
    }

    public function testFetchFail()
    {
        $ks = new KeyStore(['id' => 'secret']);
        $this->expectException(\HttpSignatures\KeyStoreException::class);
        $key = $ks->fetch('nope');
    }
}
