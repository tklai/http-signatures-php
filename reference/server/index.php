<?php
require __DIR__ . '/../../vendor/autoload.php';

$referencePublicKey = file_get_contents(__DIR__ . '/../keys/Test-public.pem');

$keyStore = new \HttpSignatures\KeyStore(['Test' => $referencePublicKey]);
$verifier = new \HttpSignatures\Verifier($keyStore);

$psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();

$creator = new \Nyholm\Psr7Server\ServerRequestCreator(
    $psr17Factory, // ServerRequestFactory
    $psr17Factory, // UriFactory
    $psr17Factory, // UploadedFileFactory
    $psr17Factory  // StreamFactory
);

$body = [];
$serverRequest = $creator->fromGlobals();

if ( $serverRequest->getHeader('Signature') ) {
    $body['headers']['Signature'] = $serverRequest->getHeader('Signature')[0];
}
if ( $serverRequest->getHeader('Authorization') ) {
  $body['headers']['Authorization'] = $serverRequest->getHeader('Authorization')[0];
}
$hostHeaders = $serverRequest->getHeader('Host');
foreach ($hostHeaders as $value) {
    if ( ! strpos($value,':') ) {
        $serverRequest = $serverRequest->withHeader('Host',$value);
        break;
    }
}
$body['signatures']['Authorization'] = $verifier->isAuthorized($serverRequest);
$body['status']['Authorization'] = $verifier->getStatus($serverRequest);
$body['signatures']['Signature'] = $verifier->isSigned($serverRequest);
$body['status']['Signature'] = $verifier->getStatus($serverRequest);

$responseBody = $psr17Factory->createStream(json_encode($body));
$response = $psr17Factory->createResponse(200)
  ->withBody($responseBody);
(new \Zend\HttpHandlerRunner\Emitter\SapiEmitter())->emit($response);

?>
