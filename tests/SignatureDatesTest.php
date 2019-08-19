<?php

namespace HttpSignatures\tests;

use PHPUnit\Framework\TestCase;
use HttpSignatures\SignatureDates;

class SignatureDatesTest extends TestCase
{
    public function testCreated()
    {
        $signatureDates = new SignatureDates();
        $this->assertTrue(
          $signatureDates->hasStarted()
        );
        $this->assertEquals(
          null,
          $signatureDates->sinceCreated()
        );
        $this->assertTrue(
          $signatureDates->hasStarted(time() + 5)
        );
        $this->assertTrue(
          $signatureDates->hasStarted(time() - 5)
        );
        $signatureDates = new SignatureDates();
        $signatureDates->setCreated(time() + 2);
        $this->assertFalse(
          $signatureDates->hasStarted()
        );
        $signatureDates->setCreated(time() - 20);
        $this->assertTrue(
          $signatureDates->hasStarted()
        );
        $this->assertTrue(
          $signatureDates->sinceCreated() <= 20
        );
        $signatureDates = new SignatureDates();
        $signatureDates->setCreated(time() + 2);
        $this->assertFalse(
          $signatureDates->hasStarted()
        );
        $signatureDates->setCreatedDrift(5);
        $this->assertTrue(
          $signatureDates->hasStarted()
        );
        $signatureDates = new SignatureDates(1);
        $this->assertTrue(
          $signatureDates->hasStarted()
        );
    }

    public function testExpires()
    {
        $signatureDates = new SignatureDates();
        $this->assertFalse(
          $signatureDates->hasExpired()
        );
        $signatureDates->setExpires(time() - 2);
        $this->assertFalse(
          $signatureDates->hasExpired(time() - 5)
        );
        $this->assertTrue(
          $signatureDates->hasExpired(time() + 5)
        );
        $signatureDates = new SignatureDates();
        $signatureDates->setExpires(time() - 2);
        $this->assertTrue(
          $signatureDates->hasExpired()
        );
        $signatureDates->setExpiresDrift(5);
        $this->assertFalse(
          $signatureDates->hasExpired()
        );
        $signatureDates->setExpiresDrift(0);
        $this->assertTrue(
          $signatureDates->hasExpired()
        );
        $signatureDates = new SignatureDates();
        $this->assertEquals(
          null,
          $signatureDates->toExpire()
        );
        $signatureDates->setExpires(time() + 20);
        $this->assertTrue(
          $signatureDates->toExpire() <= 20
        );
    }
}
