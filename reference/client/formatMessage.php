<?php

function formatMessage($refRequest, $psr17Factory) {
    $refMethod = explode(' ',$refRequest[0])[0];
    $refUri = explode(' ',$refRequest[0])[1];
    $refPath = explode('?',$refUri)[0];
    if (sizeof(explode('?',$refUri)) > 1 ) {
      $refQry = explode('?',$refUri)[1];
    } else {
      $refQry = false;
    }
    $request = new Nyholm\Psr7\Request(
      explode(' ',$refRequest[0])[0],
      'http://localhost:6789'
    );
    $reqUri = $request->getUri()
        ->withPath($refPath);
    if ( $refQry ) {
      $reqUri = $reqUri
          ->withQuery($refQry);
    }
    $request = $request->withUri($reqUri);
    $requestBody = "";
    $lineNumber = 1;
    while ( $lineNumber < sizeof($refRequest) ) {
      $line = trim($refRequest[$lineNumber]);
      if ( $line == "" ) { break; };
      $headerName = explode(':', $line)[0];
      $headerValue = trim(explode(' ',$line,2)[1]);
      $headers[] = [$headerName => $headerValue];
      $lineNumber++;
    };
    foreach ($headers as $header) {
      foreach ($header as $name => $value) {
        if ( $name == 'Host' ) {
          $request = $request->withHeader($name,$value);
        } else {
          $request = $request->withAddedHeader($name,$value);
        }
      }
    };
    $lineNumber++;
    $inBody = false;
    while ( $lineNumber < sizeof($refRequest) ) {
      if ( $inBody ) { $requestBody = $requestBody . "\n"; };
      $inBody = true;
      $requestBody = $requestBody . $refRequest[$lineNumber];
      $lineNumber++;
    };
    $request = $request->withBody($psr17Factory->createStream($requestBody));
    return $request;
}
