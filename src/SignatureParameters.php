<?php

namespace HttpSignatures;

class SignatureParameters
{
    /**
     * @param Key                $key
     * @param AlgorithmInterface $algorithm
     * @param HeaderList         $headerList
     * @param Signature          $signature
     */
    public function __construct($key, $algorithm, $headerList, $signature, $signatureDates = null)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
        $this->signature = $signature;
        $this->signatureDates = $signatureDates;
    }

    /**
     * @return string
     */
    public function string()
    {
        return implode(',', $this->parameterComponents());
    }

    /**
     * @return array
     */
    private function parameterComponents()
    {
        $components = [];
        $components[] = sprintf('keyId="%s"', $this->key->getId());
        $components[] = sprintf('algorithm="%s"', $this->algorithm->name());
        if (in_array($this->algorithm->name(), ['hs2019'])) {
            if (!empty($this->signatureDates)) {
                if (in_array(
                  '(created)',
                  $this->headerList->listHeaders()
                ) &&
                  !empty($this->signatureDates->getCreated())
                ) {
                    $components[] = sprintf('created=%s', $this->signatureDates->getCreated());
                }
                if (in_array(
                  '(expires)',
                  $this->headerList->listHeaders()
                ) &&
                  !empty($this->signatureDates->getExpires())
                ) {
                    $components[] = sprintf('expires=%s', $this->signatureDates->getExpires());
                }
            }
        }
        if ($this->headerList->headerListSpecified()) {
            $components[] = sprintf('headers="%s"', $this->headerList->string());
        }
        $components[] = sprintf('signature="%s"', $this->signatureBase64());

        return $components;
    }

    /**
     * @return string
     */
    private function signatureBase64()
    {
        return base64_encode($this->signature->string());
    }
}
