<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;
use HttpSignatures\KeyStore;
use PHPUnit\Framework\TestCase;

class VerifierContextTest extends TestCase
{
    const DATE = 'Fri, 01 Aug 2014 13:44:32 -0700';
    const DATE_DIFFERENT = 'Fri, 01 Aug 2014 13:44:33 -0700';

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * @var Request
     */
    private $signedMessage;

    /**
     * @var Request
     */
    private $authorizedMessage;

    /**
     * @var Request
     */
    private $signedAndAuthorizedMessage;

    public function setUp()
    {
        $this->setUpVerifier();
        $this->setUpSignedMessage();
        $this->setUpAuthorizedMessage();
        $this->setUpSignedAndAuthorizedMessage();
    }

    private function setUpVerifier()
    {
        // $keyStore = new KeyStore(['pda' => 'secret']);
        $this->verifierCompleteContext = new Context([
          'keys' => ['pda' => 'secret'],
          'headers' => ['(request-target)', 'date'],
        ]);
        $this->verifierEmptyContext = new Context([
        ]);
    }

    private function setUpSignedMessage()
    {
        $signatureLine = sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            '(request-target) date',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );

        $this->signedMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Signature' => $signatureLine,
            'Authorization' => 'Bearer abc123',
        ]);

        $signatureLineNoHeaders = sprintf(
            'keyId="%s",algorithm="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );

        $this->signedMessageNoHeaders = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Signature' => $signatureLineNoHeaders,
            'Authorization' => 'Bearer abc123',
        ]);
    }

    private function setUpAuthorizedMessage()
    {
        $authorizationHeader = sprintf(
            'Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            '(request-target) date',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );

        $this->authorizedMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Authorization' => $authorizationHeader,
            'Signature' => 'My Lawyer signed this',
        ]);
    }

    private function setUpSignedAndAuthorizedMessage()
    {
        $authorizationHeader = sprintf(
            'Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            '(request-target) date',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );
        $signatureHeader = sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            '(request-target) date',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );

        $this->signedAndAuthorizedMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Authorization' => $authorizationHeader,
            'Signature' => $signatureHeader,
        ]);
    }

    public function testVerifySignedMessage()
    {
        $verifier = $this->verifierCompleteContext->verifier();
        $this->assertTrue($verifier->isSigned($this->signedMessage));
        $this->assertEquals(
          "Signed with SigningString 'KHJlcXVlc3QtdGFyZ2V0KTogZ2V0IC9wYXRoP3F1ZXJ5PTEyMwpkYXRlOiBGcmksIDAxIEF1ZyAyMDE0IDEzOjQ0OjMyIC0wNzAw'",
          $verifier->getStatus()[0]
        );
        $verifier->isSigned($this->signedMessage);
        $this->assertEquals(
          1,
          sizeof($verifier->getStatus())
        );
    }

    public function testVerifyAuthorizedMessage()
    {
        $verifier = $this->verifierCompleteContext->verifier();
        $this->assertTrue($verifier->isAuthorized($this->authorizedMessage));
        $this->assertEquals(
        "Authorized with SigningString 'KHJlcXVlc3QtdGFyZ2V0KTogZ2V0IC9wYXRoP3F1ZXJ5PTEyMwpkYXRlOiBGcmksIDAxIEF1ZyAyMDE0IDEzOjQ0OjMyIC0wNzAw'",
        $verifier->getStatus()[0]
      );
        $verifier->isAuthorized($this->authorizedMessage);
        $this->assertEquals(
        1,
        sizeof($verifier->getStatus())
      );
    }

    public function testProvidedParameters()
    {
        $verifier = $this->verifierCompleteContext->verifier();
        $this->assertEquals(
          ['(request-target)', 'date'],
          $verifier->getSignatureHeaders($this->signedMessage, 'headers')
        );
        $verifier = $this->verifierCompleteContext->verifier();
        $this->assertEquals(
          ['date'],
          $verifier->getSignatureHeaders($this->signedMessageNoHeaders, 'headers')
        );
    }

    public function testVerifyInjectKey()
    {
        $dummyKey = ['abc' => 'notsosecret'];
        $usefulKey = ['pda' => 'secret'];
        $context = new Context(['keys' => $dummyKey]);
        $verifier = $context->verifier();
        $this->assertFalse($verifier->isSigned($this->signedMessage));
        $this->assertEquals(
          "Cannot locate key for supplied keyId 'pda'",
          $verifier->getStatus()[0]
        );
        $requiredKeyId = $verifier->getSignatureKeyId($this->signedMessage);
        $this->assertEquals(
          'pda',
          $requiredKeyId
        );
        $context->addKeys($usefulKey);
        $verifier = $context->verifier();
        $this->assertTrue($verifier->isSigned($this->signedMessage));
    }
}
