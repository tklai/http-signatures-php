==========
Quickstart
==========

This page provides a quick introduction to HTTP Signatures PHP library
and introductory examples.

If you have not already installed HTTP Signatures PHP library head over to the :ref:`installation`
page.

A reference signing client and verifying server are included that will
actually exchange messages over HTTP. To see the library in actions,
head over the the `Reference Implementation Guide in the file REFERENCE.md
<https://github.com/liamdennehy/http-signatures-php/blob/6.4.1/REFERENCE.md>`_.

.. _signing_quickstart:

Signing a message
==================

Once you have a PSR-7 message ready to send,
create a Context with:

* your chosen algorithm
* the list of headers to include in the signature
* the key you will use to sign the message

For these examples we will sign the method + URI (indicated by
``(request-target``) and the ``Content-Type`` header. This provides a very
basic level of protection, and you should consider the headers you sign
in your application carefully. These may also be specified by the verifier
(most often a server hosting an API or web service).

Note also that this does not apply only to HTTP requests sent by a client.
Servers can add a signature to responses that the client can verify.

Shared Secret Context (HMAC)
-------------------------------

This type of signature uses a secret key known to you and the verifier.

.. code-block:: php

  $signingContext = new \HttpSignatures\Context([
    'keys' => ['key12' => file_get_contents('/path/to/secret-key')],
    'algorithm' => 'hmac-sha256',
    'headers' => ['(request-target)', 'Date'],
  ]);

Private Key Context (RSA)
---------------------------

This type of signature uses a private key known only to you, which can be
verified using a public key that is known to anyone who wants to verify the
message.

The key file is assumed to be an unencrypted private key in PEM format.

.. code-block:: php

  $signingContext = new \HttpSignatures\Context([
    'keys' => ['key12' => file_get_contents('/path/to/privatekey.pem')],
    'algorithm' => 'rsa-sha256',
    'headers' => ['(request-target)', 'Date']
  ]);

Signing the Message:
---------------------

With your PSR-7 compliant message in ``$message``:

.. code-block:: php

  $signingContext->signer()->sign($message);

Now ``$message`` contains the ``Signature`` header:

.. code-block:: php

  print $message->getHeader('Signature')[0];
  // keyId="key12",algorithm="<yourAlgorithm>",headers="...",signature="..."

There is a similar function to add the ``Authorization: Signature`` header:

.. code-block:: php

  $signingContext->signer()->authorize($message);
 
  print $message->getHeader('Authorization')[0];
  // Signature keyId="key12",algorithm="<yourAlgorithm>",headers="...",signature="..."

Adding a Digest header while signing
-------------------------------------

Include a ``Digest`` header automatically when signing to also protect the
payload (body) of the message in addition to the request-target and headers:

.. code-block:: php

  $signingContext->signer()->signWithDigest($message);
  
  $message->headers->getHeader('Digest')[0];
  // SHA-256=<base64SHA256Digest>

Verifying a Signed Message
=============================

Most parameters are derived from the Signature in the signed message, so the
Context can be created with fewer parameters.

It is probably most useful to create a Context with multilpe keys/certificates.
the signature verifier will look up the key using the keyId attribute of the
Signature header and use that to validate the signature.

Verifying a HMAC signed message
-------------------------------------

A message signed with an hmac signature is verified using the same key as
the one used to sign the original message. Since multiple signatures may
come from multiple keys, the verifier can take an array of known keys
and will match the id of the key provided with the ``keyId`` parameter in
the received message header.

.. code-block:: php

  $verifier = new \HttpSignatures\Verifier([
    'key300' => 'some-other-secret',
    'key12' => 'your-secret-here'
  ]);

  $verifier->isSigned($message); // true or false
  // OR
  $verifier->isAuthorized($message); // true or false


Verifying a RSA signed message
-------------------------------------

An RSA signature is verified using the certificate associated with the
Private Key that created the message. Create a context by importing
the X.509 PEM format certificates in place of the 'secret':

.. code-block:: php

  $verifier = new \HttpSignatures\Verifier([
    'key12' => file_get_contents('/path/to/certificate'),
    'key87' => $someOtherCertificate
  ]);

  $verifier->isSigned($message); // true or false
  // OR
  $verifier->isAuthorized($message); // true or false


Verifying a message digest
-------------------------------------

To confirm the body has a valid digest header and the header is a valid digest
of the message body, use the ``$verifier`` from above:

.. code-block:: php

  $verifier->isValidDigest($message); // true or false

An all-in-one validation that the signature includes the digest, and the digest
is valid for the message body:

.. code-block:: php

  $verifier->isSignedWithDigest($message); // true or false
  // OR
  $verifier->isAuthorizedWithDigest($message); // true or false


Symfony compatibility
========================

Symfony requests normalize query strings which means the resulting request target can be incorrect. See https://github.com/symfony/psr-http-message-bridge/pull/30

When creating PSR-7 requests you use `withRequestTarget` to ensure the request target is correct. For example

.. code-block:: php

  use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
  use Symfony\Component\HttpFoundation\Request;

  $symfonyRequest = Request::create('/foo?b=1&a=2');
  $psrRequest = (new DiactorosFactory())
  	->createRequest($symfonyRequest)
  	->withRequestTarget($symfonyRequest->getRequestUri());
