<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../reference/client/formatMessage.php';
use HttpSignatures\Context;
use HttpSignatures\SigningString;
use HttpSignatures\HeaderList;
// if (file_exists('./invocations.json')) {
//   $invocations = json_decode(file_get_contents('./invocations.json'));
// } else {
//   $invocations->count = 1;
// };

$psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();
$allArgs = $argv;
$privateKey = 'not-a-secret';
$options['algorithm'] = 'hmac-256';
array_shift($argv);
$input = file_get_contents("php://stdin");
$tmpArgs = $argv;
foreach ($tmpArgs as $key => $value) {
  if ( strpos($value,'/') !== false ) {
    $elements = explode('/',$value);
    $tmpArgs[$key] = $elements[sizeof($elements) - 1];
  }
};
$fileName = implode(':',$tmpArgs);
file_put_contents('./invoke/' . $fileName,$input);
foreach ($tmpArgs as $key => $value) {
  if ( strpos($value,'0') ) {
    $tmpArgs[$key] = '"'.$value.'"';
  }
};
$msgIn = explode("\n",$input);
$contextParms = [];
$call=implode(' ',$argv);
$options = [];
$mode = $argv[0];
$created = null;
$expires = null;
array_shift($argv);
$context = new Context();
while ( sizeof($argv) > 0 ) {
  switch ($argv[0]) {
    case '--headers':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $headers = trim($argv[1]);
        if ( $argv[1] == "" ) {
          $headers = [];
        } else {
          $headers = explode(' ',$headers);
        };
        array_shift($argv);
      } else {
        $headers = null;
      };
      break;

    case '--private-key':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $privateKeyFile = file_get_contents($argv[1]);
        array_shift($argv);
      } else {
        print "No value provided for parameter --private-key"; exit(3);
      };
      break;

    case '--public-key':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $publicKeyFile = file_get_contents($argv[1]);
        array_shift($argv);
      } else {
        print "No value provided for parameter --public-key"; exit(3);
      };
      break;

    case '--algorithm':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $algorithm = $argv[1];
        array_shift($argv);
      } else {
        print "No value provided for parameter --algorithm"; exit(3);
      };
      break;

    case '--key-type':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['keyType'] = $argv[1];
        array_shift($argv);
      } else {
        print "No value provided for parameter --key-type"; exit(3);
      };
      break;

    case '--keyId':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['keyId'] = $argv[1];
        if (!empty($privateKeyFile)) {
          $key = [$argv[1]=>$privateKeyFile];
        } elseif (!empty($publicKeyFile)) {
          $key = [$argv[1]=>$publicKeyFile];
        }
        array_shift($argv);
      } else {
        print "No value provided for parameter --keyId"; exit(3);
      };
      break;

    case '--created':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $created = d($argv[1]);
        array_shift($argv);
      } else {
        print "No value provided for parameter --created"; exit(3);
      };
      break;

    case '--expires':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $expires = d($argv[1]);
        array_shift($argv);
      } else {
        print "No value provided for parameter --expires"; exit(3);
      };
      break;

    default:
      # code...
      break;
  };
  array_shift($argv);
};
$message = formatMessage($msgIn, $psr17Factory);
$hosts = $message->getHeader('Host');
$message = $message->withoutHeader('Host');
foreach ($hosts as $host) {
  if ($host != 'localhost:6789') {
    $message = $message->withAddedHeader('Host',$host);
  }
};
$dates = $message->getHeader('Date');
while (sizeof($dates) > 1) {
  array_shift($dates);
};
if (sizeof($dates)) {
  $message = $message->withHeader('Date',$dates[0]);
}
$body = explode("\n",(string)$message->getBody());
if (substr($body[0],0,6) == 'Date: ') {
  $message = $message->withHeader('Date',substr($body[0],6));
  array_shift($body);
  array_shift($body);
  $body=implode("\n",$body);
  $message = $message->withBody($psr17Factory->createStream($body));
}
function runTest($mode, $message, $key, $headers, $created, $expires) {
  $context = New Context();
  switch ($mode) {
    case 'canonicalize':

      $context->addKeys(['test' => 'key']);
      $context->setHeaders($headers);
      $signingString = $context->signer()->getSigningString($message);
      return $signingString;

      break;

    case 'sign':
    $contextParms['algorithm'] = $options['algorithm'];
    $signContext = new Context();
    $signContext->addKeys($key);
    $signContext->setAlgorithm($algorithm);
    $signedMessage = $defaultContext->signer()->authorize($message);
    return $signedMessage->getHeader('Authorization')[0];


      break;

    case 'verify':
      // $verfyingKey = new Key[$options['keyId'] => $options['publicKey']];
      // $keyStore = new \HttpSignatures\KeyStore([$options['keyId'] => $options['publicKey']]);
      $verifier = new \HttpSignatures\Verifier();
      $verifier->addKey($options['keyId'], $options['publicKey']);
      $result = $verifier->isAuthorized($message);
      if ( $result) {
        exit(0);
      } else {
        throw new \Exception(
          implode(' ',$tmpArgs).PHP_EOL.
          $options['keyId'] . ': ' . $message->getHeader('Authorization')[0] . $options['publicKey'], 1);

        exit(5);
      }
      break;
    default:
      print "Unknown mode $mode"; exit(2);
      break;
    };
};

function d($value)
{
  if ($value > 10000000) {
    $value = $value / 1000;
  }
  return round($value);
}
$result = runTest($mode, $message, $key, $headers, $created, $expires);
file_put_contents('./return/' . $fileName,$result);
print $result;
