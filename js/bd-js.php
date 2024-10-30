<?php
header('Content-Type: application/x-javascript');
session_start();

$no_cookies=0;
if (isset($_SESSION['bd_session']['keys']['js_cookie_name'])){
  $bd_js_cookie_name = $_SESSION['bd_session']['keys']['js_cookie_name'];
 }
 else $no_cookies=1;
if ($no_cookies)
  die();
if (isset($_SESSION['bd_session']['keys']['js_cookie_value'])){
  $bd_js_cookie_value = $_SESSION['bd_session']['keys']['js_cookie_value'];
 }else
  $no_cookies=1;
if ($no_cookies)
  die();
?>
	
function bitdefender_SetCookie( name, value, expires, path, domain, secure ) { 
	var today = new Date(); 
	today.setTime( today.getTime() ); 
	if ( expires ) { 
		expires = expires * 1000 * 60 * 60 * 24; 
	} 
	var expires_date = new Date( today.getTime() + (expires) ); 
	document.cookie = name+'='+escape( value ) + 
	  ( ( expires ) ? ';expires='+expires_date.toGMTString() : '' ) +
	  ( ( path ) ? ';path=' + path : '' ) + 
	  ( ( domain ) ? ';domain=' + domain : '' ) + 
	  ( ( secure ) ? ';secure' : '' ); 
}; 
	 

bitdefender_SetCookie(<?php echo "'$bd_js_cookie_name'"?>,<?php echo "'$bd_js_cookie_value'" ?>,'','/');

