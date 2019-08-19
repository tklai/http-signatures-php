<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class SigningString
{
    /** @var HeaderList */
    private $headerList;

    /** @var RequestInterface */
    private $message;

    /** @var SignatureDates */
    private $signatureDates;

    // TODO: Make signatureDates mandatory
    /**
     * @param HeaderList       $headerList
     * @param RequestInterface $message
     */
    public function __construct(HeaderList $headerList, $message, $signatureDates = null)
    {
        $this->headerList = $headerList;
        $this->message = $message;
        $this->signatureDates = $signatureDates;
    }

    /**
     * @return string
     */
    public function string()
    {
        return implode("\n", $this->lines());
    }

    /**
     * @return array
     */
    private function lines()
    {
        $lines = [];
        if (!is_null($this->headerList->names)) {
            foreach ($this->headerList->names as $name) {
                $lines[] = $this->line($name);
            }
        }

        return $lines;
    }

    /**
     * @param string $name
     *
     * @return string
     *
     * @throws SignedHeaderNotPresentException
     */
    private function line($name)
    {
        if (preg_match('/^\(.*\)$/', $name)) {
            switch ($name) {
            case '(request-target)':
              return sprintf('%s: %s', $name, $this->requestTarget());
              break;

            case '(created)':
              return sprintf('%s: %s', $name, $this->signatureDates->getCreated());
              break;

            case '(expires)':
              return sprintf('%s: %s', $name, $this->signatureDates->getExpires());
              break;

            default:
              throw new HeaderException("Special header '$name' not understood", 1);
              break;
          }
        } else {
            return sprintf('%s: %s', $name, $this->headerValue($name));
        }
    }

    /**
     * @param string $name
     *
     * @return string
     *
     * @throws SignedHeaderNotPresentException
     */
    private function headerValue($name)
    {
        if ($this->message->hasHeader($name)) {
            $header = '';
            $values = $this->message->getHeader($name);
            while (sizeof($values) > 0) {
                $header = $header.$values[0];
                array_shift($values);
                if (sizeof($values) > 0) {
                    $header = $header.', ';
                }
            }
            // $header = $this->message->getHeader($name);

            return $header;
        // return end($header);
        } else {
            throw new SignedHeaderNotPresentException("Header '$name' not in message");
        }
    }

    /**
     * @return string
     */
    private function requestTarget()
    {
        return sprintf(
            '%s %s',
            strtolower($this->message->getMethod()),
            $this->message->getRequestTarget()
        );
    }
}
