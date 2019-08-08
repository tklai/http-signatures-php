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
array_shift($argv);
// switch ($mode) {
//   case 'c14n':
while ( sizeof($argv) > 0 ) {
  // print $argv[0] . PHP_EOL;
  switch ($argv[0]) {
    case '--headers':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['headers'] = explode(' ',$argv[1]);
        if ( $options['headers'] == "" ) {
          $options['headers'] = false;
        }
        array_shift($argv);
      } else {
        $options['headers'] = null;
      };
      break;

    case '--private-key':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $privateKey = file_get_contents($argv[1]);
      } else {
        print "No vaue provided for parameter --private-key"; exit(3);
      };
      break;

    case '--algorithm':
      if ( sizeof($argv) > 1 && substr($argv[1],0,2) != '--' ) {
        $options['algorithm'] == $argv[1];
      } else {
        print "No vaue provided for parameter --private-key"; exit(3);
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
    $contextParms['keys']['Test'] = $privateKey;
    $contextParms['algorithm'] = $options['algorithm'];
    $defaultContext = new \HttpSignatures\Context($contextParms);
    $signedMessage = $defaultContext->signer()->sign($message);
    return $signedMessage->getHeader('Signature')[0];


      break;

    case 'verify':
      print "Not yet implemented"; exit(2);
      break;
    default:
      print "Unknown mode $mode"; exit(2);
      break;
    };
};

$result = runTest($mode, $message, $options, $privateKey);
file_put_contents('./return/' . $fileName,$result);
print $result;
