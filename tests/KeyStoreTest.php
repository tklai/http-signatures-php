<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use PHPUnit\Framework\TestCase;

class KeyStoreTest extends TestCase
{
    public function setUp()
    {
        $this->ks = new KeyStore(['first' => 'secret']);
    }

    public function testCreatedandAdd()
    {
        $this->assertEquals(
          1,
          $this->ks->count()
        );
        $ks = $this->ks;
        $this->ks->addKeys(['another' => 'secret-key']);
        $this->assertEquals(
          2,
          $this->ks->count()
        );
        $this->assertEquals(
          'secret-key',
          $this->ks->fetch('another')->getSigningKey()
        );
        $this->ks->addKeys(['another' => 'duplicate']);
    }

    public function testFetch()
    {
        $this->assertEquals(
        'secret',
        $this->ks->fetch('first')->getSigningKey()
      );
    }

    public function testFetchFail()
    {
        $this->expectException(\HttpSignatures\KeyStoreException::class);
        $key = $this->ks->fetch('nope');
    }
}
