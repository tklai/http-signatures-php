<?php
require './vendor/autoload.php';
require __DIR__ . '/formatMessage.php';

$psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();
$psr18Client = new \Buzz\Client\Curl($psr17Factory);

$refRequestFile = file(__DIR__ . '/../request.http');
$referencePrivateKeyFile = file_get_contents(__DIR__ . '/../keys/Test-private.pem');
$referencePrivateKey = ['Test' => $referencePrivateKeyFile];
$referenceRequest = formatMessage($refRequestFile,$psr17Factory);

print "==================================================" . PHP_EOL;
print "Signing HTTP Messages v10 Reference Implementation" . PHP_EOL;
print "==================================================" . PHP_EOL;
print "Using Reference Request:--------------------------" . PHP_EOL;
foreach ($refRequestFile as $line) {
  print $line;
};
print PHP_EOL;
print "--------------------------------------------------" . PHP_EOL;
print "Using Private Key:--------------------------------" . PHP_EOL;
print $referencePrivateKeyFile;
print "--------------------------------------------------" . PHP_EOL;

// Default Test
// @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.1
print "Default Test:-------------------------------------" . PHP_EOL;
$defaultTestContext = new \HttpSignatures\Context([
  'keys' => $referencePrivateKey,
  'algorithm' => 'rsa-sha256'
]);
$signedRequest = $defaultTestContext->signer()->sign($referenceRequest);
$signingString = $defaultTestContext->signer()->getSigningString($referenceRequest);
$expectedSignatureHeaderValue = trim(file_get_contents(__DIR__ . '/../headers/default-test-signature'));
if (
  $signedRequest->getHeader('Signature')[0] ==
  $expectedSignatureHeaderValue
) {
  print "Signature header correctly generated: '$expectedSignatureHeaderValue'" . PHP_EOL;
} else {
  print "Signature header NOT correctly generated: '$expectedSignatureHeaderValue'" . PHP_EOL;
};
$response = $psr18Client->sendRequest($signedRequest);
$responseObject = json_decode((string)$response->getBody());
if ($responseObject->signatures->Signature) {
    print "Server reports Signature header validated" . PHP_EOL;
} else {
    print "Server reports Signature header NOT validated !!!!!!!!!!!" . PHP_EOL;
    print "SigningString:" . base64_encode($signingString). PHP_EOL;
    print $responseObject->status->Signature[0] . PHP_EOL;
};
unset($signedRequest);
print "--------------------------------------------------" . PHP_EOL;

$authorizedRequest = $defaultTestContext->signer()->authorize($referenceRequest);
$expectedAuthorizationHeaderValue = trim(file_get_contents(__DIR__ . '/../headers/default-test-authorization'));
if (
    $authorizedRequest->getHeader('Authorization')[0] ==
    $expectedAuthorizationHeaderValue
) {
    print "Authorization header correctly generated: '$expectedAuthorizationHeaderValue'" . PHP_EOL;
  } else {
    print "Authorization header NOT correctly generated: '$expectedAuthorizationHeaderValue'" . PHP_EOL;
};
$response = $psr18Client->sendRequest($authorizedRequest);
$responseObject = json_decode((string)$response->getBody());
if ($responseObject->signatures->Authorization) {
    print "Server reports Authorization header validated" . PHP_EOL;
} else {
    print "Server reports Authorization header NOT validated !!!!!!!!!!!" . PHP_EOL;
    print "SigningString:" . base64_encode($signingString). PHP_EOL;
    print $responseObject->status->Authorization[0] . PHP_EOL;
};
print "--------------------------------------------------" . PHP_EOL;
unset($authorizedRequest);
unset($defaultTestContext);

// Basic Test
// @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.2
print "Basic Test:---------------------------------------" . PHP_EOL;
$basicTestContext = new \HttpSignatures\Context([
  'keys' => $referencePrivateKey,
  'algorithm' => 'rsa-sha256',
  'headers' => ['(request-target)', 'host', 'date']
]);
$authorizedRequest = $basicTestContext->signer()->authorize($referenceRequest);
$signingString = $basicTestContext->signer()->getSigningString($referenceRequest);
$expectedAuthorizationHeaderValue = trim(file_get_contents(__DIR__ . '/../headers/basic-test-authorization'));
if (
  $authorizedRequest->getHeader('Authorization')[0] ==
  $expectedAuthorizationHeaderValue
) {
  print "Authorization header correctly generated: '$expectedAuthorizationHeaderValue'" . PHP_EOL;
} else {
  print "Authorization header NOT correctly generated: '".$authorizedRequest->getHeader('Authorization')[0]."'" . PHP_EOL;
};
$response = $psr18Client->sendRequest($authorizedRequest);
$responseObject = json_decode((string)$response->getBody());
if ($responseObject->signatures->Authorization) {
    print "Server reports Authorization header validated" . PHP_EOL;
} else {
    print "Server reports Authorization header NOT validated !!!!!!!!!!!" . PHP_EOL;
    print "SigningString:" . base64_encode($signingString). PHP_EOL;
    print $responseObject->status->Authorization[0] . PHP_EOL;
};
print "--------------------------------------------------" . PHP_EOL;
unset($authorizedRequest);
unset($basicTestContext);

// All Headers Test
// @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.3
print "All Headers Test:---------------------------------" . PHP_EOL;
$allHeadersTestContext = new \HttpSignatures\Context([
  'keys' => $referencePrivateKey,
  'algorithm' => 'rsa-sha256',
  'headers' => ['(request-target)', 'host', 'date', 'content-type', 'digest', 'content-length']
]);
$signedRequest = $allHeadersTestContext->signer()->sign($referenceRequest);
$expectedSignatureHeaderValue = trim(file_get_contents(__DIR__ . '/../headers/all-headers-test-signature'));
if (
  $signedRequest->getHeader('Signature')[0] ==
  $expectedSignatureHeaderValue
) {
  print "Signature header correctly generated: '$expectedSignatureHeaderValue'" . PHP_EOL;
} else {
  print "Signature header NOT correctly generated: '$expectedSignatureHeaderValue'" . PHP_EOL;
};
$signingString = $allHeadersTestContext->signer()->getSigningString($referenceRequest);
$response = $psr18Client->sendRequest($signedRequest);
$responseObject = json_decode((string)$response->getBody());
if ($responseObject->signatures->Signature) {
    print "Server reports Signature header validated" . PHP_EOL;
} else {
    print "Server reports Signature header NOT validated !!!!!!!!!!!" . PHP_EOL;
    print "SigningString:" . base64_encode($signingString). PHP_EOL;
    print $responseObject->status->Authorization[0] . PHP_EOL;
};
unset($signedRequest);
print "--------------------------------------------------" . PHP_EOL;

$authorizedRequest = $allHeadersTestContext->signer()->authorize($referenceRequest);
$expectedAuthorizationHeaderValue = trim(file_get_contents(__DIR__ . '/../headers/all-headers-test-authorization'));
if (
    $authorizedRequest->getHeader('Authorization')[0] ==
    $expectedAuthorizationHeaderValue
) {
    print "Authorization header correctly generated: '$expectedAuthorizationHeaderValue'" . PHP_EOL;
  } else {
    print "Authorization header NOT correctly generated: '$expectedAuthorizationHeaderValue'" . PHP_EOL;
  };
$response = $psr18Client->sendRequest($authorizedRequest);
$responseObject = json_decode((string)$response->getBody());
if ($responseObject->signatures->Authorization) {
    print "Server reports Authorization header validated" . PHP_EOL;
} else {
    print "Server reports Authorization header NOT validated !!!!!!!!!!!" . PHP_EOL;
    print "SigningString:" . base64_encode($signingString). PHP_EOL;
    print $responseObject->status->Authorization[0] . PHP_EOL;
};
print "--------------------------------------------------" . PHP_EOL;
unset($authorizedRequest);
unset($allHeadersTestContext);
