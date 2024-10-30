<?php
/**
*
* @package BitdefenderAntispam
* @version 0.1
* @copyright (c) 2010 Bitdefender
* @license http://opensource.org/licenses/gpl-license.php GNU Public License
**/

define('BD_SCANNER_TIMEOUT', '3');

define('BD_HOST', 'nimbus.bitdefender.net');    
//if (!defined('BD_PATH')){
define('BD_PATH', '/comment/blogspam');
// }
define('BD_PORT', '80');
define('BD_TIMEOUT', '10');

define('BD_DEBUG', 0);



function bd_perform($method, $post_vars, $client_id, $charset = 'UTF-8')
{
  $post_data = array();
  if (is_array($post_vars) || is_object($post_vars))
	foreach($post_vars as $key=>$val){
	  if (is_scalar($key) && is_scalar($val) && is_string($key)){
	    $key  = strtolower($key);
	    $post_data[$key] = $val;
	  }
    }
  else 
	return -1;
  $post_data['method'] = $method;
  $post_data['client_id'] = $client_id;
  $post_data['charset'] = $charset;
  $post = json_encode($post_data);
  
  $result = '';
  $req  = "POST ".BD_PATH." HTTP/1.0\r\n";
  $req .= "Host: ".BD_HOST."\r\n";
  $req .= "Content-Type: application/json\r\n";
  $req .= "Content-Length: " . strlen($post) . "\r\n";
  $req .= "\r\n";
  $req .= $post;
  if (BD_DEBUG){
	echo  $post;
  }
  $rsp = array("","");
  if ($fs = @fsockopen(BD_HOST, BD_PORT, $errno, $errstr, BD_TIMEOUT)){
    stream_set_timeout($fs, BD_TIMEOUT);  
    fwrite($fs, $req);
    $metadata = stream_get_meta_data($fs);
    while(!feof($fs) && !$metadata['timed_out']){
      $rsp .= fgets($fs, 1160);
      $metadata = stream_get_meta_data($fs);     
    }
    fclose($fs);
    if (!$metadata['timed_out']){
      $rsp = explode("\r\n\r\n", $rsp);
    }else{
      $result['response_type'] = 'error';
      $result['message'] = 'Client timeout';
    }
  }else{
    $result['response_type'] = 'error';
    $result['message'] = $errstr;
  }
  
  if($result!='')
  	return $result;
  $status_line = explode("\r\n", $rsp[0]);
  if (count($status_line) < 1){
    $result['response_type'] = 'error';
    $result['message'] = 'Invalid HTTP response 1';
	return $result;
  }
  
  $response_code = explode(' ', $status_line[0], 3);  
  if (count($response_code) != 3){
    $result['response_type'] = 'error';
    $result['message'] = 'Invalid HTTP response 2';
	if (BD_DEBUG)
	  print_r($status_line);
	return $result;
  } else {
	$response_message = $response_code[2];
	$response_code = $response_code[1];
  }
  
  if (strncmp($response_code, '2', 1)){
	$result['response_type']='error';
	$result['message'] = $response_message;
	return $result;
  }
   
  $decoded = json_decode($rsp[1], true);
  $result['response_type'] = isset($decoded['type'])?$decoded['type']:'error';
  if (isset($result['result']) && $result['response_type']=='error' )
	$result['message'] = $decoded['value'];
  else{
	$result['status'] = isset($decoded['value'])?$decoded['value']:'';
  }
  $result['result_data'] = $decoded;	
  if (BD_DEBUG){
    echo  "<pre>";
	echo "Send data:<br>";
	print_r($post_data);
	echo "Post data: <br>";
	echo $post."<br>";
	echo "Response: <br>";
	print_r($rsp);
	echo "Decoded response: <br>";
	print_r($decoded);
	echo "Function result: <br>";
	print_r($result);
    die();
  }  
  return $result;
}

?>
