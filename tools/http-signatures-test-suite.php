<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../reference/client/formatMessage.php';
// use \HTTPSignatures\Context;
use HttpSignatures\SigningString;
use HttpSignatures\HeaderList;
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
$msgIn = explode("\n",$input);
$contextParms = [];
$call=implode(' ',$argv);
$mode = $argv[0];
$options = [];
$options['keyId'] = 'foo';
array_shift($argv);
while ( sizeof($argv) > 0 ) {
  switch ($argv[0]) {
    case '--headers':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $headerAttribute = $argv[1];
        if ( $headerAttribute == "" ) {
          $options['headers'] = [];
        } else {
          $options['headers'] = explode(' ',$argv[1]);
        // }
        // if (sizeof($headerList) == 0) {
        //   $options['headers'] = [];
        // } else {
        //   $options['headers'] = $headerList;
        };
        // $options['headers'] = explode(' ',$argv[1]);
        // if ( $options['headers'] == "" ) {
        //   $options['headers'] = false;
        // }
        array_shift($argv);
      } else {
        $options['headers'] = [];
      };
      break;

    case '--private-key':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['privateKey'] = file_get_contents($argv[1]);
      } else {
        print "No value provided for parameter --private-key"; exit(3);
      };
      break;

    case '--public-key':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['publicKey'] = file_get_contents($argv[1]);
      } else {
        print "No value provided for parameter --public-key"; exit(3);
      };
      break;

    case '--algorithm':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['algorithm'] = $argv[1];
      } else {
        print "No value provided for parameter --algorithm"; exit(3);
      };
      break;

    case '--key-type':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['keyType'] = $argv[1];
      } else {
        print "No value provided for parameter --key-type"; exit(3);
      };
      break;

    case '--keyId':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['keyId'] = $argv[1];
      } else {
        print "No value provided for parameter --keyId"; exit(3);
      };
      break;

    case '--created':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['created'] = $argv[1];
      } else {
        print "No value provided for parameter --created"; exit(3);
      };
      break;

    case '--expires':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['expires'] = $argv[1];
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
// $headerList = new HeaderList($headers);
// $ss = new SigningString($headerList, $message);
function runTest($mode, $message, $options) {
  global $privateKey;
  switch ($mode) {
    case 'c14n':

      // try {
      //   $result = $ss->string();
      // } catch (\Exception $e) {
      //   var_dump([$msgIn, $allArgs]); exit(1);
      // }
      $ssContextParms['keys']['Test'] = $privateKey;
      $ssContextParms['algorithm'] = 'hmac-sha256';
      $ssContextParms['headers'] = $options['headers'];
      $ssContext = new \HttpSignatures\Context($ssContextParms);
      $signingString = $ssContext->signer()->getSigningString($message);
      return $signingString;

      break;

    case 'sign':
    // [
    //     'keys' => ['Test' => self::referencePrivateKey],
    //     'algorithm' => 'rsa-sha256',
    //     'headers' => self::basicTestHeaders,
    // ]
    $contextParms['keys']['Test'] = $options['privateKey'];
    $contextParms['algorithm'] = $options['algorithm'];
    $defaultContext = new \HttpSignatures\Context($contextParms);
    $signedMessage = $defaultContext->signer()->sign($message);
    return $signedMessage->getHeader('Signature')[0];


      break;

    case 'verify':
      $keyStore = new \HttpSignatures\KeyStore([$options['keyId'] => $options['publicKey']]);
      $verifier = new \HttpSignatures\Verifier($keyStore);
      $result = $verifier->isAuthorized($message);
      // $contextParms['keys']['Test'] = $options['publicKey'];
      // $contextParms['algorithm'] = $options['algorithm'];
      // $verifyContext = new \HttpSignatures\Context($contextParms);
      // $result = $verifyContext->verifier->isSigned($message);
      if ( $result) {
        exit(0);
      } else {
        throw new \Exception("keyId: '{$options['keyId']}'", 1);

        exit(5);
      }
      break;
    default:
      print "Unknown mode $mode"; exit(2);
      break;
    };
};

$result = runTest($mode, $message, $options, $headerAttribute);
file_put_contents('./return/' . $fileName,$result);
print $result;
