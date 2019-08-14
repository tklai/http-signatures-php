<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Verifier
{
    /** @var KeyStoreInterface */
    private $keyStore;

    /**
     * @var string
     */
    private $status;

    /**
     * @param KeyStoreInterface $keyStore
     */
    public function __construct(KeyStoreInterface $keyStore = null, $minimumHeaders = [])
    {
        // if ( $keyStore ) {
        $this->keyStore = $keyStore;
        // };
        $this->minimumHeaders = $minimumHeaders;
        $this->status = [];
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isSigned($message)
    {
        if (is_null($this->keyStore)) {
            $this->status[] = 'No keys provided, cannot verify';

            return false;
        }
        $this->status = [];
        try {
            $verification = new Verification($message, $this->keyStore, 'Signature');
            $result = $verification->verify();
            $this->status[] =
              "Signed with SigningString '".
              base64_encode($verification->getSigningString()).
              "'";

            return $result;
        } catch (Exception $e) {
            // TODO: Match at least one header
            switch (get_class($e)) {
                case 'HttpSignatures\HeaderException':
                  $this->status[] = 'Signature header not found';

                  return false;
                  break;
                case 'HttpSignatures\SignatureParseException':
                  $this->status[] = 'Signature header malformed';

                  return false;
                  break;
                case 'HttpSignatures\SignatureException':
                  $this->status[] = $e->getMessage();

                  return false;
                  break;
                case 'HttpSignatures\SignedHeaderNotPresentException':
                  $this->status[] = $e->getMessage();

                  return false;
                  break;
                case 'HttpSignatures\KeyStoreException':
                  $this->status[] = $e->getMessage();

                  return false;
                  break;
                default:
                  $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();
                  throw $e;
                  break;
                }
        }
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isAuthorized($message)
    {
        $this->status = [];
        try {
            $verification = new Verification($message, $this->keyStore, 'Authorization');
            $result = $verification->verify();
            $this->status[] =
              "Authorized with SigningString '".
              base64_encode($verification->getSigningString()).
              "'";

            return $result;
        } catch (Exception $e) {
            // TODO: Match at least one header
            switch (get_class($e)) {
                case 'HttpSignatures\HeaderException':
                  $this->status[] = 'Authorization header not found';

                  return false;
                  break;
                case 'HttpSignatures\SignatureParseException':
                  $this->status[] = 'Authorization header malformed';

                  return false;
                  break;
                default:
                  $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();
                  throw $e;
                  break;
                }
        }
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isValidDigest($message)
    {
        $this->status = [];
        if (0 == sizeof($message->getHeader('Digest'))) {
            $this->status[] = 'Digest header mising';

            return false;
        }
        try {
            $bodyDigest = BodyDigest::fromMessage($message);
        } catch (\HttpSignatures\DigestException $e) {
            $this->status[] = $e->getMessage();

            return false;
        }

        $isValidDigest = $bodyDigest->isValid($message);
        if (!$isValidDigest) {
            $this->status[] = 'Digest header invalid';
        }

        return $isValidDigest;
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isSignedWithDigest($message)
    {
        if ($this->isValidDigest($message)) {
            if ($this->isSigned($message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isAuthorizedWithDigest($message)
    {
        if ($this->isValidDigest($message)) {
            if ($this->isAuthorized($message)) {
                return true;
            }
        }

        return false;
    }

    public function keyStore()
    {
        return $this->keyStore;
    }

    public function getStatus()
    {
        return $this->status;
    }

    public function getSignatureParameters($message)
    {
        $signatureLine = $message->getHeader('Signature')[0];
        $signatureParametersParser = new SignatureParametersParser(
            $signatureLine
        );

        return $signatureParametersParser->parse();
    }

    public function getSignatureHeaders($message, $parameter)
    {
        $parameters = $this->getSignatureParameters($message);
        if (!isset($parameters['headers'])) {
            return ['date'];
        }
        $headers = explode(' ', $parameters['headers']);

        return $headers;
    }

    public function withMinimumHeaders(array $minimumHeaders)
    {
        $this->minimumHeaders = $minimumHeaders;
    }

    public function withKeys($keys = [])
    {
        return $this;
        // TODO: Add keys to keystore
    }
}
