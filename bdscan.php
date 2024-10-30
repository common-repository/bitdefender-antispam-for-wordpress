<?php
/*
Plugin Name: BitDefender Anti-Spam
Plugin URI: http://4blogs.bitdefender.com
Description: The Anti-Spam module from Bitdefender ensures your blog stays free of unsolicited comments, by employing some state of the art scan engines and techniques, using a web service offered freely by Bitdefender. Besides the advantage of using advanced spam filtering, it also offers comment management features beyond the capabilities of Wordpress and can be configured to work from invisible (and completely non-interfering) to highly secure.
Version: 1.3.1
Author: BitDefender
*/


include_once('bdapi.php');


$bd_db_version= "1.0";
$bd_meta_log="";
$bd_feedback_message='';

$bd_plugin_path = dirname(__FILE__);
$bd_sub = strstr($bd_plugin_path,DIRECTORY_SEPARATOR."wp-content".DIRECTORY_SEPARATOR."plugins".DIRECTORY_SEPARATOR);
if (!$bd_sub)
  $bd_sub = "/wp-content/plugins/bitdefender-antispam-for-wordpress/";

if (function_exists('site_url'))
  $bd_plugin_path = site_url().$bd_sub."/";
else
  $bd_plugin_path = get_option("siteurl").$bd_sub."/";
$bd_updating_from_rescan = False;


if (bd_multisite_network()){
  add_action('network_admin_menu', 'bd_create_menu_entries');
  add_action('network_admin_notices', 'bd_check_client_id');
}else{
  add_action('admin_menu', 'bd_create_menu_entries');
  add_action('wp_ajax_bd_rescan_old_comments', 'bd_ajax_rescan_old_comments');
  add_action('admin_notices', 'bd_check_client_id');
  add_action('admin_enqueue_scripts', 'bd_enqueue_sack');
}

add_action('comment_post','bd_save_log');
add_action('preprocess_comment', 'bd_check_post',1);
add_action('wp_head', 'bd_head_intercept');
add_action('comment_form', 'bd_comment_form');
add_action('get_header', 'bd_get_header');
add_filter('comment_post_redirect', 'bd_comment_redirect');
add_action('wp_set_comment_status', 'bd_report_spam_comment');
add_action('edit_comment','bd_report_spam_comment');
add_action('admin_head','bd_admin_head');
add_action('admin_init','bd_admin_init');
add_filter('sanitize_option_bd_delete_spam_days', 'bd_sanitize_delete_days');
add_filter('sanitize_option_bd_delete_log_days',  'bd_sanitize_delete_days');
add_filter('sanitize_option_bd_automatic_spam_old_days', 'bd_sanitize_delete_days');
add_action('save_post', 'bd_save_post');
add_filter('comment_text','bd_comment_text');
add_filter('comment_row_actions', 'bd_comment_row_actions');
add_action('init', 'bd_powered_by_widget_register');


function bd_check_client_id()
{
  global $wpdb;
  
  $client_id = get_option('bd_client_id');
  $client_id = trim($client_id);
  $missing_client_id = get_option('bd_missing_client_id');
  $total = 0;
  if (!bd_multisite_network()){
	$table_name = $wpdb->prefix."bd_log";
	$table_comments = $wpdb->prefix."comments";
	$query = "SELECT  SQL_CALC_FOUND_ROWS * 
	FROM $table_name as complete,
	(SELECT comment_id, max(timestamp)  AS mt FROM  $table_name GROUP BY comment_id) AS max_timestamp,
    $table_comments AS comments
    WHERE comments.comment_ID = complete.comment_id AND
          comments.comment_approved like '0' AND
          max_timestamp.comment_id = complete.comment_id AND 
          max_timestamp.mt = complete.timestamp AND 
          (complete.action like 'moderate' OR
           complete.action like 'nothing')
   LIMIT 3";
	$wpdb->query($query);  
	$total = $wpdb->get_var( "SELECT FOUND_ROWS()" );	
  }else{
	$total = 0;
	$missing_client_id = FALSE;
  }
  if ($total>0){
?>
	<div id="message" class="updated fade"><p><strong> BitDefender Antispam: There are <?php echo $total; ?> failed scans.    <a href="plugins.php?page=bd_configure_dispacher&bd_page=rescan_comments&bd_rescan=failed"> Rescan </a>  </strong></p></div>
<?php
  }
  if ($client_id == ''){
	update_option('bd_missing_client_id', 1);
?>
	<div id="message" class="updated fade"><p><strong> In order to complete the activation of Bitdefender Antispam plugin, we kindly ask you to <a href="plugins.php?page=bd_configure_dispacher"> enter your Client Id </a>  </strong></p></div>

<?   
  } elseif ($missing_client_id){
?>
	<div id="message" class="updated fade"><p><strong> You can <a href="plugins.php?page=bd_configure_dispacher&bd_page=rescan_comments">rescan</a> existing comments  with Bitdefender Antispam.  </strong></p></div>
<?php
	update_option('bd_missing_client_id', 0);
  }
}

function bd_powered_by_widget_register()
{
  wp_register_sidebar_widget('bitdefender_antispam_widget','Powered by Bitdefender', 'bd_widget_powered_by_bitdefender');
}

function bd_widget_powered_by_bitdefender($args)
{
  global $bd_plugin_path;
  extract($args);

  echo $before_widget;
  echo $before_title;
  ?>
	Antispam protection
	<?php echo $after_title;
	echo '<div align="center"><a href="http://4blogs.bitdefender.com/badge/index_all.html">';
	echo "<img src=\"".$bd_plugin_path."/powered_by_BD.png\"></img>";
   	echo '</a></div>';
	echo $after_widget;
}

function bd_compute_failed_scans()
{
  global $wpdb;
  if (bd_multisite_network())
	return 0;

  $table_name = $wpdb->prefix."bd_log";
  $table_comments = $wpdb->prefix."comments";
  $query = "SELECT  SQL_CALC_FOUND_ROWS *                                                                                  
    FROM $table_name as complete,                                                                                           
    (SELECT comment_id, max(timestamp)  AS mt FROM  $table_name GROUP BY comment_id) AS max_timestamp,                          $table_comments AS comments                                                                                             
    WHERE comments.comment_ID = complete.comment_id AND
          max_timestamp.comment_id = complete.comment_id AND                                                                
          max_timestamp.mt = complete.timestamp AND
          (complete.action like 'moderate' OR
           complete.action like 'nothing') 
   LIMIT 1";
  $wpdb->query($query);
  $total = $wpdb->get_var( "SELECT FOUND_ROWS()" );
  
  return $total;
}

function is_old_comment($comment_date, $post_id)
{
  if (!bd_get_option('bd_automatic_spam_old_posts'))
	return FALSE;
  $days = intval(bd_get_option('bd_automatic_spam_old_days'));
  if (! $post_id)
	return FALSE;
  $post = get_post($post_id);	
  $then = strtotime($post->post_date_gmt);
  if ($then == -1 || !$then)
	return FALSE;
  $now = $comment_date;
  $diff = $now - $then;
  return ($diff > 60*60*24*$days);  
}

function bd_get_option($name)
{
  if (bd_multisite_network())
	return get_blog_option(1, $name);
  else
	return get_option($name);   
}

function bd_update_option($name, $value)
{
  if (bd_multisite_network())
	update_blog_option(1, $name, $value);
  else
	update_option($name, $value);   
}

function bd_check_post($c)
{
  global $bd_meta_log;
  
  if(!isset($_SESSION)){
    session_start();
  }

  $comment = array();
  foreach($c as $key=>$val)
    if (get_magic_quotes_gpc())
      $comment[stripslashes($key)] = stripslashes($val);
    else
      $comment[$key] = $val;
  $comment['client_type'] = "blog";
  if ($comment['comment_type'] == '')
    $comment['comment_type'] = 'comment';
  $comment['client'] = get_option('home');
  $comment['language'] = bd_get_option('bd_blog_language');
  $comment['http_referer'] = $_SERVER['HTTP_REFERER'];
  $comment['comment_agent'] = $_SERVER['HTTP_USER_AGENT'];
  $comment['comment_author_ip'] = $_SERVER['REMOTE_ADDR'];
  $comment['comment_date_gmt'] = gmdate('Y-m-d H:m:s');
  if (!bd_multisite_network()){
	$comment['current_failed_scans'] = bd_compute_failed_scans();
  }
  $comment['global_failed_scans'] = bd_get_option('bd_global_failed_scans');
  include("bdrevision.php");
  $comment['plugin_revision'] = $bd_revision;
  $user= @wp_get_current_user();
  if ($user && $user->id!=0){
    $comment['user_logged_in'] = 1;
    $comment['user_id'] = $user->id;
  }
  else
    $comment['user_logged_in'] = 0;
  
  if (isset($_SESSION['bd_session']['keys'])){    
    $keys = $_SESSION['bd_session']['keys'];
    $comment['js_enabled'] = ($_POST[$keys['input_field_name']] == $keys['input_field_value'])?1:0;
    $comment['js_cookies_enabled'] = ($_COOKIE[$keys['js_cookie_name']] == $keys['js_cookie_value'])?1:0;
    $comment['cookies_enabled'] = ($_COOKIE[$keys['cookie_name']] == $keys['cookie_value'])?1:0;
    $comment['session_time'] = time() - $_SESSION['bd_session']['started'];
    $comment['img_loaded'] = $_SESSION['bd_session']['img_loaded']?1:0;
    $comment['session_expired'] = 0;
  }else{
    $comment['session_expired'] = 1;
  } 
  $comment['blog_charset'] = bd_get_option('blog_charset');
  $comment['cyrillic_filter'] =  bd_get_option('bd_filter_cyrillic')?"1":"0";
  $comment['asiatic_filter']  =  bd_get_option('bd_filter_asiatic')?"1":"0";;
  $comment['aggresivity_level']  =  bd_get_option('bd_aggresivity_level');
  $comment['whitelisted_ip'] = bd_ip_in_whitelist($_SERVER['REMOTE_ADDR'])?'1':'0';
  if (is_old_comment(gmdate('U'), $comment['comment_post_ID'])){
	$comment['old_spam'] = 1;
  } else {
	$comment['old_spam'] = 0;
  }
  $rez = bd_perform("scan",$comment, bd_get_option('bd_client_id'));
  $action="";
  $verbose_rez="";
  if (BD_DEBUG){
    echo "<pre>";
    print_r($comment);
    print_r($_COOKIE);
    echo "SESSION<br>";
    print_r($_SESSION);
    echo "REZ<br>";
    print_r($rez);
    echo "USER<br>";
    die();
  };
  if ($comment['whitelisted_ip'] == '1'){
	$rez['response_type'] = 'success';
	$rez['status'] = 'whitelisted';
  } else{
	if ($comment['old_spam'] == 1){
	  $rez['response_type'] = 'success';
	  $rez['status'] = 'spam';
	}
  }
  if ($rez['response_type']=='error'){
	bd_update_option('bd_global_failed_scans', bd_get_option('bd_global_failed_scans') + 1);
	$verbose_rez = $rez['message'];    
	if (bd_get_option('bd_moderate_on_scan_error')){
	  $action = 'moderate';	 
	  add_filter('pre_comment_approved', create_function('$a', 'return \'0\';'));		
	}else{
	  $action = 'nothing';	 
	}
  }elseif ($rez['response_type']=='success'){
    $action = 'pass';
    $verbose_rez = 'legit';
    if ($rez['status'] == 'spam') {
      add_filter('pre_comment_approved', create_function('$a', 'return \'spam\';'));		
      $action='move to spam';
	  if ($comment['old_spam'] == 1){
		$verbose_rez = 'oldspam';
	  }else{
		$verbose_rez = 'spam';
	  }
	  bd_update_option('bd_spam_count', bd_get_option('bd_spam_count') + 1);
    }else{
	  if ($comment['whitelisted_ip'] == '1'){
		$action = 'pass';
		$verbose_rez = 'Ip in whitelist';		
	  }
	  bd_update_option('bd_legit_count', bd_get_option('bd_legit_count') + 1);
	}  
	if (!bd_multisite_network()){
	  bd_send_unscanned_comments();
	}
  }
  $bd_meta_log[0]=$verbose_rez;
  $bd_meta_log[1]=$action;
  bd_delete_old_spam();
  bd_delete_old_logs();
  return $c;
}

function bd_rescan_comment($comment_id, $update_counts = TRUE, $retry_rescan = FALSE)
{
  global  $bd_meta_log, $bd_updating_from_rescan;

  if ( !current_user_can('moderate_comments' ))
	return 'error';

  $c = get_comment($comment_id, ARRAY_A);
  $comment = array();
  foreach($c as $key=>$val)
	$comment[$key] = $val;
  if (!$comment['comment_content'])
	return 0;
  $comment['user_logged_in'] = $comment['user_id']!=0 ? 1 : 0 ;
  $comment['client_type'] = "blog";
  $comment['client'] = get_option('home');
  $comment['blog_charset'] = get_option('blog_charset');
  $comment['rescan'] = 1;
  $comment['language'] = get_option('bd_blog_language');
  $comment['cyrillic_filter'] =  get_option('bd_filter_cyrillic')?"1":"0";
  $comment['asiatic_filter']  =  get_option('bd_filter_asiatic')?"1":"0";;
  $comment['aggresivity_level']  =  get_option('bd_aggresivity_level');
  include("bdrevision.php");
  $comment['plugin_revision'] = $bd_revision;
  if ($comment['comment_type'] == '')
	$comment['comment_type'] = 'comment';
  $comment['whitelisted_ip'] = bd_ip_in_whitelist($comment['comment_author_IP'])?'1':'0';
  if (is_old_comment(strtotime($comment['comment_date_gmt']), $comment['comment_post_ID']) ){
	$comment['old_spam'] = 1;
  } else {
	$comment['old_spam'] = 0;
  }
  $count = 0;
  do{
	$scan_rez = bd_perform("scan", $comment, get_option('bd_client_id'));
	$count += 1;
  }while($retry_rescan && $count<4 && $scan_rez['response_type'] == 'error');
  
  if ($comment['whitelisted_ip'] == '1'){
	$scan_rez['response_type'] = 'success';
	$scan_rez['status'] = 'whitelisted';
  }else{
	if ($comment['old_spam']){
	  $scan_rez['response_type'] = 'success';
	  $scan_rez['status'] = 'spam';
	}
  }   
  if ($scan_rez['response_type'] == 'error'){ 
	update_option('bd_global_failed_scans', get_option('bd_global_failed_scans') + 1);
	$action = 'nothing';	   
  } elseif ($scan_rez['response_type']=='success'){
	$action = 'pass';
	$verbose_rez = 'Rescan: legit';	
	$moderation_activated = get_option('comment_moderation');
	if (!$moderation_activated){
	  $c['comment_approved'] = '1';
	}else{
	  if (!$c['comment_approved'] == '1')
		$c['comment_approved'] = '0';
	}
	if ($scan_rez['status'] == 'spam') {
	  $action='move to spam';
	  if ($comment['old_spam'] == 1){
		$verbose_rez = 'Rescan: oldspam';
	  }else{
		$verbose_rez = 'Rescan: spam';
	  }
	  $c['comment_approved'] = 'spam'; 
	  if ($update_counts)
		update_option('bd_spam_count', get_option('bd_spam_count') + 1);		
	}else{
	  if ($comment['whitelisted_ip'] == '1'){
		$action = 'pass';
		$verbose_rez = 'Rescan: Ip in whitelist';		
	  }
	  if ($update_counts)
		update_option('bd_legit_count', get_option('bd_legit_count') + 1);
	}
	$bd_updating_from_rescan = True;
	wp_update_comment($c);
  }
  $bd_meta_log[0] = $verbose_rez;
  $bd_meta_log[1] = $action;
  bd_save_log($c['comment_ID']);
  return $scan_rez['response_type'];
}

function bd_send_unscanned_comments()
{
  global $wpdb;
  
  $table_name = $wpdb->prefix."bd_log";
  $table_comments = $wpdb->prefix."comments";
  $query = "SELECT  * 
	FROM $table_name as complete,
	(SELECT comment_id, max(timestamp)  AS mt FROM  $table_name GROUP BY comment_id) AS max_timestamp,
    $table_comments AS comments
    WHERE comments.comment_ID = complete.comment_id AND
          comments.comment_approved like '0' AND
          max_timestamp.comment_id = complete.comment_id AND 
          max_timestamp.mt = complete.timestamp AND 
          (complete.action like 'moderate' OR
           complete.action like 'nothing')
   LIMIT 3";
   
  // $wpdb->show_errors();
  $rez = $wpdb->get_results($query);
  $total = $wpdb->num_rows;
  if (!$total)
	return;  
  for($i = 0; $i<$total; $i++){
	bd_rescan_comment($rez[$i]->comment_ID);
  }
}

function bd_generate_keys()
{
  srand(time());
  $keys['js_cookie_name'] = rand();
  $keys['js_cookie_value'] = rand();
  $keys['input_field_name'] = rand();
  $keys['input_field_value'] = rand();

  $keys['cookie_name'] = rand();
  $keys['cookie_value'] = rand();
  return $keys;
}  

function bd_comment_text($text)
{
  global $comment, $wpdb;
 
  if (bd_multisite_network())
	return $text;
  if ($comment->comment_approved == 'spam'){
	$id = $comment->comment_ID;
	$count = $wpdb->get_var($wpdb->prepare('SELECT * FROM '.$wpdb->prefix.'bd_log  WHERE message LIKE "spam"  AND comment_id = '.$id));
	if ($count)
	  return "[Bitdefender SPAM]" . $text;
  }
  return $text;
}

function bd_save_post($post_id)
{
  $post = false;
  if (function_exists("wp_is_post_revision"))
    $post = wp_is_post_revision($post_id);
  if ($post === false)
    $post = $post_id;
  $p = get_post($post);
  if ($p->post_status != 'publish' || $p->post_type != 'post')
    return;
  $p->post_date_gmt = strtotime($p->post_date_gmt);
  $p->post_password = ($p->post_password != '')?1:0;
  $p->post_modified_gmt = strtotime($p->post_modified_gmt);
  if ($p->post_content_filtered != '')
    $p->post_content = $post_content_filtered;

  $rez = bd_perform("report_post", $p, bd_get_option('bd_client_id'));
}

function bd_enqueue_sack()
{
  $bd_page = isset($_GET['bd_page'])?$_GET['bd_page']:'';
  if ($bd_page == 'do_rescan_comments'){
    wp_enqueue_script( 'sack' );
    wp_enqueue_script( 'json2' );	
  }
}

function bd_admin_init()
{

  $bd_page = isset($_GET['bd_page'])?$_GET['bd_page']:'';
  if($bd_page == 'send_feedback'){
    bd_send_feedback();  
	die();
  }
  $action = isset($_GET['action'])?$_GET['action']:'';

  if ($action == 'bd_blacklist_ip' or $action == 'bd_unblacklist_ip' or $action == 'bd_whitelist_ip' or $action == 'bd_unwhitelist_ip'){
	$comment_id = absint($_GET['c']);
	if ( !$comment = get_comment( $comment_id ) )
	  wp_die( __('Oops, no comment with this ID.'));
	if ( !current_user_can('edit_post', $comment->comment_post_ID) )
	  wp_die( __('You are not allowed to edit comments on this post.') );
	if ($action == 'bd_blacklist_ip' or $action == 'bd_unblacklist_ip')
	  bd_update_blacklist($comment_id);
	else
	  bd_update_whitelist($comment_id);
	$redir = admin_url('edit-comments.php');
	if ( '' != wp_get_referer() &&  false === strpos(wp_get_referer(), 'comment.php') )
	  $redir = wp_get_referer();
	elseif ( '' != wp_get_original_referer())
	  $redir = wp_get_original_referer();
	else
	  $redir = admin_url('edit-comments.php');
	wp_redirect($redir);
	die();
  }else if ($action == 'bd_rescan_comment'){
	$comment_id = absint($_GET['c']);
	if ( !$comment = get_comment( $comment_id ) )
	  wp_die( __('Oops, no comment with this ID.'));
	if ( !current_user_can('edit_post', $comment->comment_post_ID) )
	  wp_die( __('You are not allowed to edit comments on this post.') );
	if ( !current_user_can('moderate_comments' ))
	  return 'error';
	bd_rescan_comment($comment_id, FALSE, TRUE);
	$redir = remove_query_arg(array('c','action'));	
	wp_redirect($redir);
	die();
  }
  
}

function bd_delete_old_spam()
{
  global $wpdb;
  
  $now = current_time('mysql', 1);
  $interval = bd_sanitize_delete_days(bd_get_option('bd_delete_spam_days'));
  $wpdb->query('DELETE FROM '.$wpdb->prefix."comments WHERE DATE_SUB('$now', INTERVAL $interval DAY) > comment_date_gmt AND comment_approved='spam'");
}

function bd_delete_old_logs()
{
  global $wpdb;
  
  $now = current_time('mysql', 1);
  $interval = bd_sanitize_delete_days(bd_get_option('bd_delete_log_days'));
  $table_name = $wpdb->prefix."bd_log";
  if (bd_multisite_network()){
	$table_name = $wpdb->base_prefix."bd_log";
  }
  $wpdb->query("DELETE FROM ".$table_name." WHERE DATE_SUB('$now', INTERVAL $interval DAY) > timestamp");
}

function bd_sanitize_delete_days($value)
{
  $value = (int) $value;
  if ( empty($value) ) $value = 30;
  if ( $value < -1 ) $value = abs($value);
  return $value;
}

function bd_admin_head()
{
  global $bd_plugin_path;
 
  echo "<link rel='stylesheet' href='".$bd_plugin_path."bdscan.css' type='text/css' media='all' />";
}

function bd_save_log($comment_id)
{
  global $bd_meta_log, $wpdb;
  
  if (!isset($bd_meta_log) || !isset($bd_meta_log[0]) || !isset($bd_meta_log[1]))
      return;
  $msg="";   
  $action = $bd_meta_log[1];
  $msg = $bd_meta_log[0];
  $table_name = $wpdb->prefix."bd_log";
  if (bd_multisite_network())
	$table_name = $wpdb->base_prefix."bd_log";
  $q = "INSERT INTO ".$table_name." (comment_id,format, message, action) VALUES (".$comment_id.",1,'".$msg."','".$action."')";
  $wpdb->query($q);
}

function bd_get_header()
{
  if(!isset($_SESSION)){
    session_start(); 
  }
  if (!isset($_SESSION['bd_session']['started']))
    $_SESSION['bd_session']['started'] = time();
  if (!isset($_COOKIE["bd_check_cookie"]))
    setcookie("bd_check_cookie","1");
  if (!isset($_SESSION['bd_session']['keys'])){
    $keys = bd_generate_keys();
    $_SESSION['bd_session']['keys']=$keys;
  }else
    $keys = $_SESSION['bd_session']['keys'];
  if (!isset($_COOKIE[$keys["cookie_name"]]))
    setcookie($keys["cookie_name"],$keys["cookie_value"]);
}


function bd_comment_redirect($location)
{  
  if (!$_SESSION){
    session_start();
  }
  $rez = $location;
  if (!isset($_COOKIE["bd_check_cookie"])){
    $rez = str_replace("?", "?".htmlspecialchars(SID)."&", $location);  
  }
  return $rez;
}

function bd_comment_form($post_id)
{
  global $bd_plugin_path;

  if (isset($_SESSION['bd_session']['keys']))
    $keys = $_SESSION['bd_session']['keys'];
  else
    return;			// This should not happen!!!
  $sname = session_name();
  $sid = session_id();  
  ?>
    <input type="hidden" name="<?php echo $sname?>" value="<?php echo $sid ?>"/>  
       <input type="hidden" id="bd_scan_input" name="<?php echo $keys['input_field_name'] ?>" value=""/>
       <script type="text/javascript">
       document.getElementById("bd_scan_input").value = "<?php echo $keys['input_field_value'] ?>"; 
  </script>  
     <img src="<?php echo $bd_plugin_path.'img.php?'.$sname.'='.$sid ?>" alt="" height="1" width="1">
      <?php
      }

function bd_head_intercept()
{ 
  global $bd_plugin_path;
  echo '<script type="text/javascript" src="'.$bd_plugin_path.'/js/bd-js.php"></script> ';  
}

function bd_create_menu_entries()
{
  if (!function_exists('add_submenu_page')){
	return;
  }
  if(bd_multisite_network()){
	add_submenu_page('plugins.php', 'BitDefender Antispam', "BitDefender Antispam",  'manage_network', 'bd_configure_dispacher', 'bd_configure_dispacher');
  }else{
	  add_submenu_page('plugins.php', 'BitDefender Antispam', "BitDefender Antispam",  'moderate_comments', 'bd_configure_dispacher', 'bd_configure_dispacher');
	
  }
}

function bd_configure_dispacher()
{
  $bd_page = isset($_GET['bd_page'])?$_GET['bd_page']:'';
						
  if ($bd_page == 'log' )
    bd_show_log();
  elseif ($bd_page == 'rescan_comments')
	bd_rescan_old_comments();
  elseif ($bd_page == 'do_rescan_comments')
	bd_do_rescan_old_comments();
  else
    bd_configure_page();   
}


function bd_send_feedback()
{
  if (!isset($_POST['bd_feedback']))
	return;
  include("bdrevision.php");
  $post_data['plugin_revision'] = $bd_revision;
  $post_data['feedback'] = $_POST['bd_feedback'];
  $post_data['client']   = get_option('home');
  
  $rez = bd_perform("feedback", $post_data, bd_get_option('bd_client_id'));
  if (strstr($rez[0],"200")===False){	// Some error   
	//    $bd_feedback_message = $rez[1];
  }
  $to = add_query_arg(array("updated" => "feedback"));
  $to = remove_query_arg("bd_page", $to);

  wp_redirect($to);

}

function bd_format_log($log)
{
  if ($log->format!=1)
    return $log;
  if (isset($log->comment_content)){
    $url=add_query_arg(array("action" => "update_blacklist",
			     "comment_id" => $log->comment_id));	
	if ($log->comment_author_IP){
	  if ($log->blacklisted)
		$log->comment_author_IP .= "<br> <a href=\"$url\" >Remove IP from blacklist</a>";
	  else
		$log->comment_author_IP .= "<br> <a href=\"$url\" >Blacklist IP</a>";
	}
	$log->comment_content = substr($log->comment_content, 0, 20);	
	$log->comment_content.= '<br> <a href="comment.php?action=editcomment&c='.$log->comment_ID.'" >Edit</a>';	
	$rescanurl = add_query_arg(array("action" => "bd_rescan_comment", "c" => $log->comment_ID));	
	$log->comment_content.= "&nbsp | &nbsp<a href=\"$rescanurl\" >Rescan</a>";	
  }
  return $log;
}

function bd_ajax_rescan_old_comments()
{ 
  global $wpdb, $bd_meta_log;
  
  check_ajax_referer();
  $result = array('status' => 'success');
  if ( !current_user_can('moderate_comments' )){
	$result['status'] = 'error';
	$result['message'] = 'You are not allowed to edit comments.';
	echo json_encode($result);
	die();
  }
  if (!isset($_POST['start'])){
	$result['status'] = 'error';
	$result['message'] = 'Start index not found.';
	echo json_encode($result);
	die();
  }
	
  $start = intval($_POST['start']);  
  $time = time();
  $query = bd_construct_rescan_query($start, 5);
  if ($query == -1){
	$result['status'] = 'error';
	$result['message'] = 'Nothing to scan';
	echo json_encode($result);
	die();
  }	
  $comments = $wpdb->get_results($query);  
  
  $total = $wpdb->num_rows;
  
  if (!$total){
	$result['done'] = 0;
	echo json_encode($result);
	die();
  }
  for($i = 0; $i < $total; $i++){
	$tmp = bd_rescan_comment($comments[$i]->comment_ID, FALSE, TRUE);
	if ($tmp == 'error'){
	  $result['status'] = 'error';
	  $result['message'] = $bd_meta_log[0];
	  echo json_encode($result);
	  die();
	}
	//sleep(3);
  }  	
  $diff = time()-$time;
  $result['done'] = $total;
  $result['last_index'] = $comments[$i-1]->comment_ID;
  $result['time'] = $diff;
  $result['start'] = $start;
  $result['query'] = $query;  
  echo json_encode($result);
  die();
}

function bd_construct_rescan_query($start, $limit)
{
  global $wpdb;
  
  $conditions = array();
  if($_REQUEST['bd_approved_comments'])
	$conditions[] = "'1'";
  if ($_REQUEST['bd_moderation_queue'])
	$conditions[] = "'0'";
  if ($_REQUEST['bd_spam_comments'])
	$conditions[] = "'spam'";
  if ($_REQUEST['bd_trash_comments'])
	$conditions[] = "'trash'";
  if (!count($conditions) and !$_REQUEST['bd_failed_comments']){
	return -1;
  } 
  $query1 = $query2 = '';
  if (count($conditions)){
	$condition = implode(",", $conditions);  
	$query1 = 'SELECT SQL_CALC_FOUND_ROWS comment_ID FROM '. $wpdb->prefix . 'comments WHERE comment_approved IN ('.$condition.')  AND  comment_ID > '.$start;
  }

  if ($_REQUEST['bd_failed_comments']){
	$table_name = $wpdb->prefix."bd_log";
	$table_comments = $wpdb->prefix."comments";
	$calc_rows = $query1==''?'SQL_CALC_FOUND_ROWS':'';
	$query2 = "SELECT $calc_rows comments.comment_ID as comment_ID
      	FROM $table_name as complete,
     	(SELECT comment_id, max(timestamp)  AS mt FROM  $table_name GROUP BY comment_id) AS max_timestamp,
         $table_comments AS comments
        WHERE comments.comment_ID = complete.comment_id AND
           max_timestamp.comment_id = complete.comment_id AND 
           max_timestamp.mt = complete.timestamp AND 
           (complete.action like 'moderate' OR
            complete.action like 'nothing')";	
  }
  if ($query1!=''  && $query2!='')
	$query = "( $query1 ) UNION DISTINCT ( $query2 )";
  else
	$query = $query1.$query2;
  if ($query=='')
	return -1;  
  $query .= ' ORDER BY comment_ID ASC LIMIT '.$limit;	
  return $query;
}

function bd_do_rescan_old_comments()
{	
  global $wpdb;
  
  bd_designed_menu();
  if ( !current_user_can('moderate_comments' ))
	wp_die( __('You are not allowed to edit comments.') );
  $query = bd_construct_rescan_query(0,1);

  $error = '';
  if( $query != -1 ){
	$wpdb->query($query);  
	$total = $wpdb->get_var( "SELECT FOUND_ROWS()" );	
	if (!$total)
	  $error = 'No comments to scan';
  }else{
	$error = 'No comments to scan';
  }
  $nonce = wp_create_nonce();
?>
 
<script type="text/javascript">   
   function bd_set_rescan_error(message)
   {
	 text = document.getElementById("bd_scanning_text");
	 if (!text)
	   return;
	 if (message == "")
	   text.innerHTML = "Error scanning comments. Try again latter.";
	 else
	   text.innerHTML = "Error: "+message+"<br>Try again latter.";
	 bd_update_button('Go back');	 
   }  
  function bd_update_button(message)
  {
	button = document.getElementById("bd_submit");
	if (!button)
	  return;
	button.value = message;
  }

  function bd_on_ajax_completion(ajax)
  {
	try{
	  response = JSON.parse( ajax.response );
	}catch(exception){
	  bd_set_rescan_error("Invalid response from server");
	  return;
	}
	if (response.status == 'error'){	  
	  bd_set_rescan_error("Got message: " + response.message);
	  return;
	}
	done = parseInt(response.done);	
	if (!done){
	  bd_update_button('Go back');
	  scanning = document.getElementById("bd_scanning_message");
	  if (scanning)
		scanning.innerHTML="";		  
	  return;
	}
	processed = document.getElementById('bd_completed');
	if (!processed)
	  return;
	p = parseInt(processed.innerHTML);
	processed.innerHTML = p + done;
	last_index = parseInt(response.last_index);
	
	var ajax = new sack();	 
	ajax.method = 'POST';	 
	ajax.requestFile = ajaxurl;
	ajax.onCompletion = function(){ bd_on_ajax_completion(ajax); };	   
	ajax.onError = function(){ bd_on_ajax_error(ajax); };
	ajax.setVar('start', last_index);	   
	ajax.setVar('action', 'bd_rescan_old_comments');	   
<?php
	if($_REQUEST['bd_approved_comments'])
	  echo "ajax.setVar('bd_approved_comments', '1');";
	if ($_REQUEST['bd_moderation_queue'])
	  echo "ajax.setVar('bd_moderation_queue', '1');";
	if ($_REQUEST['bd_spam_comments'])
	  echo "ajax.setVar('bd_spam_comments', '1');";
	if ($_REQUEST['bd_trash_comments'])
	  echo "ajax.setVar('bd_trash_comments', '1');";
	if ($_REQUEST['bd_failed_comments'])
	  echo "ajax.setVar('bd_failed_comments', '1');";
	echo "ajax.setVar('_ajax_nonce','$nonce');"
?>   
	ajax.runAJAX();
  } 
  
  function bd_on_ajax_error(ajax)
  {
	bd_set_rescan_error(ajax.response + ajax.responseStatus[0] + ajax.responseStatus[1]);
  }
  
  function bd_start_ajax_rescan()
  {

	var ajax = new sack();	 
	ajax.method = 'POST';	 
	ajax.requestFile = ajaxurl;
	ajax.onCompletion = function(){ bd_on_ajax_completion(ajax); };	   
	ajax.onError = function(){ bd_on_ajax_error(ajax); };
	ajax.setVar('action', 'bd_rescan_old_comments');	   
	ajax.setVar('start', 0);	   
<?php
	if($_REQUEST['bd_approved_comments'])
	  echo "ajax.setVar('bd_approved_comments', '1');";
	if ($_REQUEST['bd_moderation_queue'])
	  echo "ajax.setVar('bd_moderation_queue', '1');";
	if ($_REQUEST['bd_spam_comments'])
	  echo "ajax.setVar('bd_spam_comments', '1');";
	if ($_REQUEST['bd_trash_comments'])
	  echo "ajax.setVar('bd_trash_comments', '1');";
	if ($_REQUEST['bd_failed_comments'])
	  echo "ajax.setVar('bd_failed_comments', '1');";
	echo "ajax.setVar('_ajax_nonce','$nonce');"
?>   

	ajax.runAJAX();
  }
<?php
	if (!$error){
?>
  if (window.attachEvent) 
	 {window.attachEvent('onload', bd_start_ajax_rescan);}
  else if (window.addEventListener) 
	{window.addEventListener('load', bd_start_ajax_rescan, false);}
  else 
	{document.addEventListener('load', bd_start_ajax_rescan, false);}    
<?php 
	} 
?>
</script>

<div id="bd_table2">
 <div id="bd_table_h">
	<div id="bd_thl"></div>
      Scan existing comments
    <div id="bd_thr"></div>
 </div>    
    <div id="bd_table">
     <div id="bd_table_left">
	<span id="bd_scanning_text">
<?php 
	if ($error) {
	  echo $error; 
?>
   <p class="submit" id="bd_submit">
    <input type="button" name="Submit" value="<?php  _e('Go back') ?>" onclick="javascript:history.go(-1)"/>
   </p>
<?php
	}else{
?>
	<span id="bd_scanning_message">
		Scanning, please wait... <br>
    </span>
 	Completed <span id="bd_completed">0</span> of <span id="bd_total"><?php echo $total; ?></span> comments.
   </span>
   <p class="submit">
    <input id="bd_submit" type="button" name="Submit" value="<?php  _e('Abort') ?>" onclick="javascript:history.go(-2)"/>
   </p>
<?php     };																													   
?>																							   
  </div>
</div>
</div>
</div>
<?php     
}

function bd_rescan_old_comments()
{
  global $wpdb;  

  if (!current_user_can('moderate_comments' ))
	wp_die( __('You are not allowed to edit comments.') );
  $table_name = $wpdb->prefix."bd_log";
  $table_comments = $wpdb->prefix."comments";
  $query = "SELECT  count(*) as total
	FROM $table_name as complete,
	(SELECT comment_id, max(timestamp)  AS mt FROM  $table_name GROUP BY comment_id) AS max_timestamp,
    $table_comments AS comments
    WHERE comments.comment_ID = complete.comment_id AND
          max_timestamp.comment_id = complete.comment_id AND 
          max_timestamp.mt = complete.timestamp AND 
          (complete.action like 'moderate' OR
           complete.action like 'nothing')";
  $rez = $wpdb->get_results($query);
  $failed = $rez[0]->total;
  $tmp = $wpdb->get_results('SELECT comment_approved, count(*) as total FROM '. $wpdb->prefix . 'comments GROUP BY comment_approved');
  $total = count($tmp);
  $moderation = $approved = $spam = $trash =  0;
  
  for($i=0; $i<$total; $i++){
	switch ($tmp[$i]->comment_approved){
	case '0': $moderation = $tmp[$i]->total;
	  break;
	case '1': $approved = $tmp[$i]->total;
	  break;
	case 'spam': $spam = $tmp[$i]->total;
	  break;
	case 'trash': $trash= $tmp[$i]->total;
	  break;
	}
  }
  bd_designed_menu();
  $rescan_failed = (isset($_GET['bd_rescan']) && ($_GET['bd_rescan']=='failed')) ? ' CHECKED ' : '';
?>
<div id="bd_table2">
 <div id="bd_table_h">
	<div id="bd_thl"></div>
      Scan existing comments
    <div id="bd_thr"></div>
 </div>    
    <div id="bd_table">
     <div id="bd_table_left">
   <form method="GET" action="">
   <span class="bd_row">Scan approved comments (<?php echo $approved; ?>)
   <input class="bd_check" type="checkbox" name="bd_approved_comments" value="1" <?php if(!$approved) echo "DISABLED"; ?> />
   <br/>
   <span class="bd_small"></span>   
  	<span class="bd_row">Scan comments in moderation queue (<?php echo $moderation; ?>)
	  <input class="bd_check" type="checkbox" name="bd_moderation_queue" value="1" 
	  <?php 
	  if(!$moderation) 
		 echo "DISABLED"; 
	  else { 
		if ($rescan_failed=='') 
		  echo "CHECKED";
	  };?> />
   </span> <br/>
    <span class="bd_small"></span>
  	<span class="bd_row">Scan comments marked as spam (<?php echo $spam; ?>)
		 <input class="bd_check" type="checkbox" name="bd_spam_comments" value="1" <?php if(!$spam) echo "DISABLED"; ?>  />
   </span> <br/>
    <span class="bd_small"></span>

  	<span class="bd_row">Scan comments in trash (<?php echo $trash; ?>)
         <input class="bd_check" type="checkbox" name="bd_trash_comments" value="1" <?php if(!$trash) echo "DISABLED"; ?>/>
   </span> <br/>
    <span class="bd_small"></span>
   <span class="bd_row">Retry failed scans(<?php echo $failed; ?>)
	   <input class="bd_check" type="checkbox" name="bd_failed_comments" value="1" <?php if(!$failed) echo " DISABLED "; echo $rescan_failed; ?> />
   </span> <br/>
    <span class="bd_small"></span>
   <center>
   <p class="submit" id="bd_submit">
     <input type="submit" name="Submit" value="<?php  _e('Start') ?>" />
      &nbsp&nbsp&nbsp&nbsp

    <input type="button" name="Submit" value="<?php  _e('Skip') ?>" onclick="javascript:history.go(-1)"/>

    </p>
   <input type="hidden" name="page" value="bd_configure_dispacher">
   <input type="hidden" name="bd_page" value="do_rescan_comments">
   </form>
</center>
  </div>
</div>
</div>
</div>
<?php
   
}

function bd_show_log()
{
  global $wpdb;
  
  $action = isset($_GET['action']) ? $_GET['action']:0;
  if ($action == "update_blacklist") {
    $comment_id = isset($_GET['comment_id'])?$_GET['comment_id']:0;
    if ($comment_id)
      bd_update_blacklist($comment_id);
  };

  $table_name = $wpdb->prefix . "bd_log";
  if(bd_multisite_network())
	$table_name = $wpdb->base_prefix . "bd_log";
  $comments_per_page = 15;
  $current_page = (isset($_GET['apage']))?intval($_GET['apage']):1;
  if ($current_page<1)
    $current_page=1;

  $search_dirty = ( isset($_GET['s']) ) ? $_GET['s'] : '';
  $search = attribute_escape( $search_dirty ); // XXX more sql escaping???
  $search = trim($search);
  $start_limit = ($current_page-1) * $comments_per_page;
  $end_limit = $comments_per_page;
  $total = -1;
  $retried = false;
  $logs_len=-1;
  $nonce = wp_create_nonce("bd_nonce");
  while(!$retried && ($logs_len<=0)){
    if ($logs_len==0 || $current_page==1){
      $retried = true;
      $start_limit = 0;				
      $current_page = 1;
    }
    $wpdb->show_errors();
    $comment_table = $wpdb->prefix."comments";
    $wpdb->show_errors();
    $blacklist = get_option('blacklist_keys');
	if(bd_multisite_network()){
	  $query = ("SELECT SQL_CALC_FOUND_ROWS * 
                               FROM ".$table_name." 
                               WHERE concat(message,action) LIKE '%".$search."%' 
                               ORDER by timestamp DESC  LIMIT ".$start_limit.", ".$end_limit);
	}else{
	  $query = ("SELECT SQL_CALC_FOUND_ROWS *, LOCATE(comment_author_IP, '$blacklist') AS blacklisted
                               FROM ".$table_name." 
                               LEFT JOIN $comment_table ON $table_name.comment_id=$comment_table.comment_ID 
                               WHERE concat(message,comment_author_IP,action) LIKE '%".$search."%' 
                               ORDER by timestamp DESC  LIMIT ".$start_limit.", ".$end_limit);
    }
	$logs= $wpdb->get_results($query);
    $total = $wpdb->get_var( "SELECT FOUND_ROWS()" );
    $logs_len=count($logs);   
  }
  $total_pages = ceil($total / $comments_per_page);
  if ($current_page>$total_pages)
    $current_page=$total_pages;
  $base = add_query_arg('apage','%#%');
  $pagination_links=array();
  $k=0; 
  if ($current_page>1){
    $link=str_replace("%#%",$current_page-1,$base);
    $prev_text = '&laquo';
    $pagination_links[$k++]="<a class='prev page-numbers' href='" . clean_url($link) . "'>$prev_text</a>";
  }

  $end_size = 1;
  $mid_size = 3;
  $dots=false;
  for($i=1;$i<=$total_pages;$i++){
    if ($i==$current_page){
      $pagination_links[$k++]="<span class='page-numbers current'>$i</span>";
      $dots=true;
    }else{
      if ( ($i<=$end_size)  || ($total_pages-$end_size<$i) || (abs($current_page-$i) < $mid_size)){
	$link=str_replace("%#%",$i,$base);
	$pagination_links[$k++]="<a class='page-numbers' href='" . clean_url($link) . "'>$i</a>";
	$dots=true;
      } else if ($dots){
	$pagination_links[$k++]="<span class='page-numbers dots'>...</span>";
	$dots=false;
      }     
    } 
  }
  if ($current_page<$total_pages && $total_pages>=2){
    $link=str_replace("%#%",$current_page+1,$base);
    $next_text = '&raquo;';
    $pagination_links[$k++]="<a class='next page-numbers' href='" . clean_url($link) . "'>$next_text</a>";
  }
  $s = isset($_GET['s'])?$_GET['s']:'';
  $search_excerpt = esc_html( stripslashes( $s ) );
  if (function_exists('wp_html_excerpt'))
      $search_excerpt = wp_html_excerpt($search_excerpt, 50);
  //print_r($pagination_links);
  //echo "TOTAL: $total $logs_len";
?>

<?php
	bd_designed_menu();
?>
<br>
<form id="search-form" action="" method="get">
<p class="search-box">
	<label class="hidden" for="comment-search-input"><?php _e( 'Search Logs' ); ?>:</label>
	<input type="text" class="search-input" id="comment-search-input" name="s" value="<?php the_search_query(); ?>" />
	<input type="submit" value="<?php _e( 'Search Logs' ); ?>" class="button" />
</p>  

<br class="clear"/>

<?php if ( isset($_GET['s']) && $_GET['s'] )
	printf( '<span class="subtitle">' . sprintf( __( 'Search results for &#8220;%s&#8221;' ), $search_excerpt. '</span>')); ?>																				   
       <input type="hidden" name="page" value="<?php echo $_GET['page']; ?>" /> 
       <input type="hidden" name="bd_page" value="<?php echo $_GET['bd_page']; ?>" /> 
</form>

<?php
   if (!$total){
     _e('No results found.');
   }else{
?>
											       
  <table class="widefat">
    <thead>
    <tr>
    <th scope="col">Timestamp </th>
<?php if(!bd_multisite_network()) { ?>
    <th scope="col">Author IP</th>
    <th scope="col">Comment</th>
<?php } ?>
    <th scope="col">Message</th>
    <th scope="col">Action</th>
    </tr>
    </thead>
    
    <tbody>
     <?php
     foreach($logs as $log){
       $log = bd_format_log($log);
     ?>
    <tr>
     <td><?php echo $log->timestamp ?></td>
<?php if(!bd_multisite_network()) { ?>
     <td><?php echo $log->comment_author_IP ?></td>
	 <td><?php echo $log->comment_content ?></td>
<?php } ?>
     <td><?php echo $log->message ?></td>
     <td><?php echo $log->action ?></td>
  </tr>
<?php
  };
   }
?>
    </tbody>
</table>

<div class="tablenav">
<?php
  $k=count($pagination_links);
  if ($k>1){
    echo "<div class='tablenav-pages'>";
    for ($i=0; $i<$k; $i++){
      echo $pagination_links[$i]."\n";
    }
    echo "</div>";
  }
?>
<br class="clear" />
</div>

</div>

</div>
<?php
   
   }


function bd_plugin_deactivate()
{
  include("bdrevision.php");
  $post_data['plugin_revision'] = $bd_revision;
  $post_data['client']   = get_option('home');	
  $rez = bd_perform('deactivate', $post_data, bd_get_option('bd_client_id'));  
  if (function_exists('is_multisite') && is_multisite() &&
	  isset($_GET['networkwide']) && ($_GET['networkwide'] == 1)){
	update_site_option('bd_multisite_mode' , 0);   
  }
}

function bd_multisite_network()
{
  return function_exists('is_multisite') && is_multisite() &&
	get_site_option('bd_multisite_mode')==1;
}

function bd_plugin_activate()
{
  global $wpdb, $bd_db_version;

  if (function_exists('is_multisite') && is_multisite() &&
	  isset($_GET['networkwide']) && ($_GET['networkwide'] == 1)){
	update_site_option('bd_multisite_mode' , 1);   
  }

  if (function_exists('add_option')){
    add_option('bd_client_id');
	add_option('bd_missing_client_id');
    add_option('bd_whitelist_ip','');
    add_option('bd_delete_spam_days',30);
    add_option('bd_delete_log_days',30);
	add_option('bd_blog_language',0);
	add_option('bd_filter_cyrillic',0);	
	add_option('bd_filter_asiatic',0);
	add_option('bd_global_failed_scans', 0);
	add_option('bd_aggresivity_level', 1); //0-permissive, 1-normal, 2-high
    add_option('bd_automatic_spam_old_posts', 1);
    add_option('bd_automatic_spam_old_days', 30);
    add_option('bd_moderate_on_scan_error',0);
  }
  

  $table_name = $wpdb->prefix . "bd_log";
  if (bd_multisite_network())
	$table_name = $wpdb->base_prefix . "bd_log";
  if($wpdb->get_var("show tables like '$table_name'") != $table_name) {
	$sql = "CREATE TABLE " . $table_name . " (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            format int(11) NOT NULL,
            comment_id int(11) NULL, 
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            message VARCHAR(255),
            action  VARCHAR(255),
            UNIQUE KEY id (id)
            );";
	add_option("bd_db_version", $bd_db_version);
	$wpdb->query($sql);
  }
	 
  $spam_count = bd_get_option('bd_spam_count',-1);
  if ($spam_count == -1){
	$count = $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$table_name.' WHERE message="spam"'));  
	bd_update_option('bd_spam_count', $count);
  }
  $clean_count = bd_get_option('bd_legit_count',-1);
  if ($clean_count == -1){
	$count = $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$table_name.' WHERE message LIKE "%clean%" OR message LIKE "%legit%" OR message LIKE "%whitelist%"'));
	bd_update_option('bd_legit_count', $count);
  }
  {
	include("bdrevision.php");
	$post_data['plugin_revision'] = $bd_revision;
	$post_data['client']  = get_option('home');	
	$rez = bd_perform('activate', $post_data, bd_get_option('bd_client_id'));
  }
}

register_activation_hook( __FILE__, 'bd_plugin_activate');
register_deactivation_hook(__FILE__, 'bd_plugin_deactivate');

function bd_designed_menu(){
  global $bd_plugin_path;
?>
	<?php if (isset($_GET['updated']) && $_GET['updated']!='feedback')  : ?>
		<div id="message" class="updated fade"><p><strong><?php _e('Settings saved.') ?></strong></p></div>
	 <?php endif; ?>

		<?php if (isset($_GET['updated']) && $_GET['updated'] == 'feedback')  : ?>
	 <div id="message" class="updated fade"><p><strong><?php _e('Feedback sent. Thank you!') ?></strong></p></div>
	<?php endif; ?>

<div id="bd_wrapper">
<div id="bd_meniu">
	<div id="bd_csoon"></div>	
	<div id="bd_m_left"></div>
    <div id="bd_buttons">
    	<ul>
    	    <li class="bd_meniu_li"><a href="plugins.php?page=bd_configure_dispacher">Configuration</a></li>
            <li class="bd_meniu_li"><a href="plugins.php?page=bd_configure_dispacher&bd_page=log">Logs</a></li>
            <li class="bd_meniu_li"><a class="inactive" href="">BitDefender Goodies</a><br/></li>
            <li class="bd_last"><a href="http://4blogs.bitdefender.com"><div id="bd_m_right"></div></a></li>
        </ul>
    </div>
</div>
<?php  
}

function bd_configure_page()
{
  global $bd_plugin_path, $wpdb;
  
  $selected_language=bd_get_option('bd_blog_language');
  bd_designed_menu();
  $now = time();
  $then = $now-60*60*24*6;
  $then = date('Y-m-d', $then);
  $chart_data = array();
  $table_name = $wpdb->prefix."bd_log";
  if (bd_multisite_network())
	$table_name = $wpdb->base_prefix."bd_log";
  $query = "SELECT count(*) as total,unix_timestamp(timestamp) as date FROM ".$table_name.
	                           " WHERE timestamp > '".$then."'
                               GROUP BY date(timestamp)";
  $totals= $wpdb->get_results($query);
  $spams= $wpdb->get_results("SELECT count(*) as total,unix_timestamp(timestamp) as date FROM ".$table_name. 
                               " WHERE timestamp > '".$then."' AND message LIKE '%spam%'
                               GROUP BY date(timestamp)");  
  for ($i=6;$i>=0;$i--){	
	$then = $now-($i*60*60*24);
	$key = date('j M', $then);
	$chart_data[$key] = array(0,0);	  
  }
  $max = 3;
  foreach($totals as $row){
	$key = date('j M', $row->date);
	$chart_data[$key][0] = $row->total;
	$max = max($max, $row->total);

  }
  foreach($spams as $row){
	$key = date('j M', $row->date);
	$chart_data[$key][1] = $row->total;
	$max = max($max, $row->total);
  } 
  $show_detection_chart = (bd_get_option('bd_spam_count')+bd_get_option('bd_legit_count')) !=0;
  bd_send_feedback();
  if($show_detection_chart){
?>
<script type="text/javascript" src="http://www.google.com/jsapi"></script> 
<script type="text/javascript"> 
  google.load("visualization", "1", {packages:["piechart"]});
  google.load("visualization", "1", {packages:["corechart"]});
  google.setOnLoadCallback(drawChart);  
  
  function drawChart() { 
	var pie_data = new google.visualization.DataTable();
	var chart_data = new google.visualization.DataTable();
	
	pie_data.addColumn('string', 'Task');
	pie_data.addColumn('number', 'Numar');
	pie_data.addRows(2);
	pie_data.setValue(0, 0, 'Spam');
	pie_data.setValue(0, 1, <?php echo bd_get_option('bd_spam_count')?bd_get_option('bd_spam_count'):0; ?>);
	pie_data.setValue(1, 0, 'Legit');
	pie_data.setValue(1, 1, <?php echo bd_get_option('bd_legit_count')?bd_get_option('bd_legit_count'):0; ?>);
	var pie = new google.visualization.PieChart(document.getElementById('bd_pie_div'));
	pie.draw(pie_data, {width: 400, height: 240, is3D: true,  
		  colors:[{color:'orange', darker:'darkorange'}, {color:'#00A000', darker:'#000000'}],
		  title: 'Bitdefender Stats'});
	chart_data.addColumn('string', 'Day');
	chart_data.addColumn('number', 'Total');
	chart_data.addColumn('number', 'Spam');
<?php
	
	foreach($chart_data as $date=>$values){
	  echo 'chart_data.addRow([ "'.$date.'",'.$values[0].','.$values[1].']);';
	}
?>
   
	var chart = new google.visualization.AreaChart(document.getElementById('bd_chart_div'));
	chart.draw(chart_data, {width: 400, height: 240, title: 'Comments',
		  vAxis: {minValue:0, maxValue:<?php echo $max ?>},
		  hAxis: {title: 'Day', titleTextStyle: {color: '#FF0000'}}			
	  });

  }
</script>

<div id="bd_table1">
<div id="bd_table_h">
	<div id="bd_thl"></div>
     DETECTION CHART
    <div id="bd_thr"></div>
</div>
<div id="bd_table">
    <table table-layout="fixed">
    <tr><td width="300">
   <div id="bd_pie_div" width="300"></div>
   </td><td width="400">
   <div id="bd_chart_div"></div>
   </td></tr>
   </table>
</div>
</div>
<?php  
	} 
  if (bd_multisite_network()){
	$options_action = "../options.php";
  }else{
	$options_action = "options.php";
  }
?>
<div id="bd_table2">
<div id="bd_table_h">
	<div id="bd_thl"></div>
       FILTERING OPTIONS	   
    <div id="bd_thr"></div>
</div>

 <form method="post" action="<?php echo $options_action ?>">
   <?php echo wp_nonce_field('update-options') ?>

<div id="bd_table">
  <div id="bd_table_left">
   <span class="bd_row">BitDefender Client ID 
   <input type="text"  class="bd_id" name="bd_client_id" value="<?php echo get_option('bd_client_id') ?>" />
   <br/>
   <span class="bd_small">Enter your e-mail address to identify yourself to the BitDefender AntiSpam API. This identifies your blog to the BitDefender servers hosting the scanning services.</span>
   <div style="clear:both"></div>
   <span class="bd_row">Blog language 
   	   <select class="bd_id" name="bd_blog_language">
 	     <option <?php if ($selected_language=="0") echo 'selected="yes"' ?> value="0"></option>
		 <option <?php if ($selected_language=="aa") echo 'selected="yes"' ?> value="aa">Afar</option>
		 <option <?php if ($selected_language=="ab") echo 'selected="yes"' ?> value="ab">Abkhazian</option>
		 <option <?php if ($selected_language=="af") echo 'selected="yes"' ?> value="af">Afrikaans</option>
		 <option <?php if ($selected_language=="ak") echo 'selected="yes"' ?> value="ak">Akan</option>
		 <option <?php if ($selected_language=="sq") echo 'selected="yes"' ?> value="sq">Albanian</option>
		 <option <?php if ($selected_language=="am") echo 'selected="yes"' ?> value="am">Amharic</option>
		 <option <?php if ($selected_language=="ar") echo 'selected="yes"' ?> value="ar">Arabic</option>
		 <option <?php if ($selected_language=="an") echo 'selected="yes"' ?> value="an">Aragonese</option>
		 <option <?php if ($selected_language=="hy") echo 'selected="yes"' ?> value="hy">Armenian</option>
		 <option <?php if ($selected_language=="as") echo 'selected="yes"' ?> value="as">Assamese</option>
		 <option <?php if ($selected_language=="av") echo 'selected="yes"' ?> value="av">Avaric</option>
		 <option <?php if ($selected_language=="ae") echo 'selected="yes"' ?> value="ae">Avestan</option>
		 <option <?php if ($selected_language=="ay") echo 'selected="yes"' ?> value="ay">Aymara</option>
		 <option <?php if ($selected_language=="az") echo 'selected="yes"' ?> value="az">Azerbaijani</option>
		 <option <?php if ($selected_language=="ba") echo 'selected="yes"' ?> value="ba">Bashkir</option>
		 <option <?php if ($selected_language=="bm") echo 'selected="yes"' ?> value="bm">Bambara</option>
		 <option <?php if ($selected_language=="eu") echo 'selected="yes"' ?> value="eu">Basque</option>
		 <option <?php if ($selected_language=="be") echo 'selected="yes"' ?> value="be">Belarusian</option>
		 <option <?php if ($selected_language=="bn") echo 'selected="yes"' ?> value="bn">Bengali</option>
		 <option <?php if ($selected_language=="bh") echo 'selected="yes"' ?> value="bh">Bihari languages</option>
		 <option <?php if ($selected_language=="bi") echo 'selected="yes"' ?> value="bi">Bislama</option>
		 <option <?php if ($selected_language=="bs") echo 'selected="yes"' ?> value="bs">Bosnian</option>
		 <option <?php if ($selected_language=="br") echo 'selected="yes"' ?> value="br">Breton</option>
		 <option <?php if ($selected_language=="bg") echo 'selected="yes"' ?> value="bg">Bulgarian</option>
		 <option <?php if ($selected_language=="my") echo 'selected="yes"' ?> value="my">Burmese</option>
		 <option <?php if ($selected_language=="ca") echo 'selected="yes"' ?> value="ca">Catalan</option>
		 <option <?php if ($selected_language=="ch") echo 'selected="yes"' ?> value="ch">Chamorro</option>
		 <option <?php if ($selected_language=="ce") echo 'selected="yes"' ?> value="ce">Chechen</option>
		 <option <?php if ($selected_language=="zh") echo 'selected="yes"' ?> value="zh">Chinese</option>
		 <option <?php if ($selected_language=="cu") echo 'selected="yes"' ?> value="cu">Church Slavic</option>
		 <option <?php if ($selected_language=="cv") echo 'selected="yes"' ?> value="cv">Chuvash</option>
		 <option <?php if ($selected_language=="kw") echo 'selected="yes"' ?> value="kw">Cornish</option>
		 <option <?php if ($selected_language=="co") echo 'selected="yes"' ?> value="co">Corsican</option>
		 <option <?php if ($selected_language=="cr") echo 'selected="yes"' ?> value="cr">Cree</option>
		 <option <?php if ($selected_language=="cs") echo 'selected="yes"' ?> value="cs">Czech</option>
		 <option <?php if ($selected_language=="da") echo 'selected="yes"' ?> value="da">Danish</option>
		 <option <?php if ($selected_language=="dv") echo 'selected="yes"' ?> value="dv">Divehi</option>
		 <option <?php if ($selected_language=="nl") echo 'selected="yes"' ?> value="nl">Dutch</option>
		 <option <?php if ($selected_language=="dz") echo 'selected="yes"' ?> value="dz">Dzongkha</option>
		 <option <?php if ($selected_language=="en") echo 'selected="yes"' ?> value="en">English</option>
		 <option <?php if ($selected_language=="eo") echo 'selected="yes"' ?> value="eo">Esperanto</option>
		 <option <?php if ($selected_language=="et") echo 'selected="yes"' ?> value="et">Estonian</option>
		 <option <?php if ($selected_language=="ee") echo 'selected="yes"' ?> value="ee">Ewe</option>
		 <option <?php if ($selected_language=="fo") echo 'selected="yes"' ?> value="fo">Faroese</option>
		 <option <?php if ($selected_language=="fj") echo 'selected="yes"' ?> value="fj">Fijian</option>
		 <option <?php if ($selected_language=="fi") echo 'selected="yes"' ?> value="fi">Finnish</option>
		 <option <?php if ($selected_language=="fr") echo 'selected="yes"' ?> value="fr">French</option>
		 <option <?php if ($selected_language=="fy") echo 'selected="yes"' ?> value="fy">Western Frisian</option>
		 <option <?php if ($selected_language=="ff") echo 'selected="yes"' ?> value="ff">Fulah</option>
		 <option <?php if ($selected_language=="ka") echo 'selected="yes"' ?> value="ka">Georgian</option>
		 <option <?php if ($selected_language=="de") echo 'selected="yes"' ?> value="de">German</option>
		 <option <?php if ($selected_language=="gd") echo 'selected="yes"' ?> value="gd">Gaelic</option>
		 <option <?php if ($selected_language=="ga") echo 'selected="yes"' ?> value="ga">Irish</option>
		 <option <?php if ($selected_language=="gl") echo 'selected="yes"' ?> value="gl">Galician</option>
		 <option <?php if ($selected_language=="gv") echo 'selected="yes"' ?> value="gv">Manx</option>
		 <option <?php if ($selected_language=="el") echo 'selected="yes"' ?> value="el">Greek, Modern (1453-)</option>
		 <option <?php if ($selected_language=="gn") echo 'selected="yes"' ?> value="gn">Guarani</option>
		 <option <?php if ($selected_language=="gu") echo 'selected="yes"' ?> value="gu">Gujarati</option>
		 <option <?php if ($selected_language=="ht") echo 'selected="yes"' ?> value="ht">Haitian</option>
		 <option <?php if ($selected_language=="ha") echo 'selected="yes"' ?> value="ha">Hausa</option>
		 <option <?php if ($selected_language=="he") echo 'selected="yes"' ?> value="he">Hebrew</option>
		 <option <?php if ($selected_language=="hz") echo 'selected="yes"' ?> value="hz">Herero</option>
		 <option <?php if ($selected_language=="hi") echo 'selected="yes"' ?> value="hi">Hindi</option>
		 <option <?php if ($selected_language=="ho") echo 'selected="yes"' ?> value="ho">Hiri Motu</option>
		 <option <?php if ($selected_language=="hr") echo 'selected="yes"' ?> value="hr">Croatian</option>
		 <option <?php if ($selected_language=="hu") echo 'selected="yes"' ?> value="hu">Hungarian</option>
		 <option <?php if ($selected_language=="ig") echo 'selected="yes"' ?> value="ig">Igbo</option>
		 <option <?php if ($selected_language=="is") echo 'selected="yes"' ?> value="is">Icelandic</option>
		 <option <?php if ($selected_language=="io") echo 'selected="yes"' ?> value="io">Ido</option>
		 <option <?php if ($selected_language=="ii") echo 'selected="yes"' ?> value="ii">Sichuan Yi</option>
		 <option <?php if ($selected_language=="iu") echo 'selected="yes"' ?> value="iu">Inuktitut</option>
		 <option <?php if ($selected_language=="ie") echo 'selected="yes"' ?> value="ie">Interlingue</option>
		 <option <?php if ($selected_language=="ia") echo 'selected="yes"' ?> value="ia">Interlingua (I.A.L.A.)</option>
		 <option <?php if ($selected_language=="id") echo 'selected="yes"' ?> value="id">Indonesian</option>
		 <option <?php if ($selected_language=="ik") echo 'selected="yes"' ?> value="ik">Inupiaq</option>
		 <option <?php if ($selected_language=="it") echo 'selected="yes"' ?> value="it">Italian</option>
		 <option <?php if ($selected_language=="jv") echo 'selected="yes"' ?> value="jv">Javanese</option>
		 <option <?php if ($selected_language=="ja") echo 'selected="yes"' ?> value="ja">Japanese</option>
		 <option <?php if ($selected_language=="kl") echo 'selected="yes"' ?> value="kl">Kalaallisut</option>
		 <option <?php if ($selected_language=="kn") echo 'selected="yes"' ?> value="kn">Kannada</option>
		 <option <?php if ($selected_language=="ks") echo 'selected="yes"' ?> value="ks">Kashmiri</option>
		 <option <?php if ($selected_language=="kr") echo 'selected="yes"' ?> value="kr">Kanuri</option>
		 <option <?php if ($selected_language=="kk") echo 'selected="yes"' ?> value="kk">Kazakh</option>
		 <option <?php if ($selected_language=="km") echo 'selected="yes"' ?> value="km">Central Khmer</option>
		 <option <?php if ($selected_language=="ki") echo 'selected="yes"' ?> value="ki">Kikuyu</option>
		 <option <?php if ($selected_language=="rw") echo 'selected="yes"' ?> value="rw">Kinyarwanda</option>
		 <option <?php if ($selected_language=="ky") echo 'selected="yes"' ?> value="ky">Kirghiz</option>
		 <option <?php if ($selected_language=="kv") echo 'selected="yes"' ?> value="kv">Komi</option>
		 <option <?php if ($selected_language=="kg") echo 'selected="yes"' ?> value="kg">Kongo</option>
		 <option <?php if ($selected_language=="ko") echo 'selected="yes"' ?> value="ko">Korean</option>
		 <option <?php if ($selected_language=="kj") echo 'selected="yes"' ?> value="kj">Kuanyama</option>
		 <option <?php if ($selected_language=="ku") echo 'selected="yes"' ?> value="ku">Kurdish</option>
		 <option <?php if ($selected_language=="lo") echo 'selected="yes"' ?> value="lo">Lao</option>
		 <option <?php if ($selected_language=="la") echo 'selected="yes"' ?> value="la">Latin</option>
		 <option <?php if ($selected_language=="lv") echo 'selected="yes"' ?> value="lv">Latvian</option>
		 <option <?php if ($selected_language=="li") echo 'selected="yes"' ?> value="li">Limburgan</option>
		 <option <?php if ($selected_language=="ln") echo 'selected="yes"' ?> value="ln">Lingala</option>
		 <option <?php if ($selected_language=="lt") echo 'selected="yes"' ?> value="lt">Lithuanian</option>
		 <option <?php if ($selected_language=="lb") echo 'selected="yes"' ?> value="lb">Luxembourgish</option>
		 <option <?php if ($selected_language=="lu") echo 'selected="yes"' ?> value="lu">Luba-Katanga</option>
		 <option <?php if ($selected_language=="lg") echo 'selected="yes"' ?> value="lg">Ganda</option>
		 <option <?php if ($selected_language=="mk") echo 'selected="yes"' ?> value="mk">Macedonian</option>
		 <option <?php if ($selected_language=="mh") echo 'selected="yes"' ?> value="mh">Marshallese</option>
		 <option <?php if ($selected_language=="ml") echo 'selected="yes"' ?> value="ml">Malayalam</option>
		 <option <?php if ($selected_language=="mi") echo 'selected="yes"' ?> value="mi">Maori</option>
		 <option <?php if ($selected_language=="mr") echo 'selected="yes"' ?> value="mr">Marathi</option>
		 <option <?php if ($selected_language=="ms") echo 'selected="yes"' ?> value="ms">Malay</option>
		 <option <?php if ($selected_language=="mg") echo 'selected="yes"' ?> value="mg">Malagasy</option>
		 <option <?php if ($selected_language=="mt") echo 'selected="yes"' ?> value="mt">Maltese</option>
		 <option <?php if ($selected_language=="mn") echo 'selected="yes"' ?> value="mn">Mongolian</option>
		 <option <?php if ($selected_language=="na") echo 'selected="yes"' ?> value="na">Nauru</option>
		 <option <?php if ($selected_language=="nv") echo 'selected="yes"' ?> value="nv">Navajo</option>
		 <option <?php if ($selected_language=="nr") echo 'selected="yes"' ?> value="nr">Ndebele, South</option>
		 <option <?php if ($selected_language=="nd") echo 'selected="yes"' ?> value="nd">Ndebele, North</option>
		 <option <?php if ($selected_language=="ng") echo 'selected="yes"' ?> value="ng">Ndonga</option>
		 <option <?php if ($selected_language=="ne") echo 'selected="yes"' ?> value="ne">Nepali</option>
		 <option <?php if ($selected_language=="nn") echo 'selected="yes"' ?> value="nn">Norwegian Nynorsk</option>
		 <option <?php if ($selected_language=="nb") echo 'selected="yes"' ?> value="nb">Bokmål, Norwegian</option>
		 <option <?php if ($selected_language=="no") echo 'selected="yes"' ?> value="no">Norwegian</option>
		 <option <?php if ($selected_language=="ny") echo 'selected="yes"' ?> value="ny">Chichewa</option>
		 <option <?php if ($selected_language=="oc") echo 'selected="yes"' ?> value="oc">Occitan (post 1500)</option>
		 <option <?php if ($selected_language=="oj") echo 'selected="yes"' ?> value="oj">Ojibwa</option>
		 <option <?php if ($selected_language=="or") echo 'selected="yes"' ?> value="or">Oriya</option>
		 <option <?php if ($selected_language=="om") echo 'selected="yes"' ?> value="om">Oromo</option>
		 <option <?php if ($selected_language=="os") echo 'selected="yes"' ?> value="os">Ossetian</option>
		 <option <?php if ($selected_language=="pa") echo 'selected="yes"' ?> value="pa">Panjabi</option>
		 <option <?php if ($selected_language=="fa") echo 'selected="yes"' ?> value="fa">Persian</option>
		 <option <?php if ($selected_language=="pi") echo 'selected="yes"' ?> value="pi">Pali</option>
		 <option <?php if ($selected_language=="pl") echo 'selected="yes"' ?> value="pl">Polish</option>
		 <option <?php if ($selected_language=="pt") echo 'selected="yes"' ?> value="pt">Portuguese</option>
		 <option <?php if ($selected_language=="ps") echo 'selected="yes"' ?> value="ps">Pushto</option>
		 <option <?php if ($selected_language=="qu") echo 'selected="yes"' ?> value="qu">Quechua</option>
		 <option <?php if ($selected_language=="rm") echo 'selected="yes"' ?> value="rm">Romansh</option>
		 <option <?php if ($selected_language=="ro") echo 'selected="yes"' ?> value="ro">Romanian</option>
		 <option <?php if ($selected_language=="rn") echo 'selected="yes"' ?> value="rn">Rundi</option>
		 <option <?php if ($selected_language=="ru") echo 'selected="yes"' ?> value="ru">Russian</option>
		 <option <?php if ($selected_language=="sg") echo 'selected="yes"' ?> value="sg">Sango</option>
		 <option <?php if ($selected_language=="sa") echo 'selected="yes"' ?> value="sa">Sanskrit</option>
		 <option <?php if ($selected_language=="si") echo 'selected="yes"' ?> value="si">Sinhala</option>
		 <option <?php if ($selected_language=="sk") echo 'selected="yes"' ?> value="sk">Slovak</option>
		 <option <?php if ($selected_language=="sl") echo 'selected="yes"' ?> value="sl">Slovenian</option>
		 <option <?php if ($selected_language=="se") echo 'selected="yes"' ?> value="se">Northern Sami</option>
		 <option <?php if ($selected_language=="sm") echo 'selected="yes"' ?> value="sm">Samoan</option>
		 <option <?php if ($selected_language=="sn") echo 'selected="yes"' ?> value="sn">Shona</option>
		 <option <?php if ($selected_language=="sd") echo 'selected="yes"' ?> value="sd">Sindhi</option>
		 <option <?php if ($selected_language=="so") echo 'selected="yes"' ?> value="so">Somali</option>
		 <option <?php if ($selected_language=="st") echo 'selected="yes"' ?> value="st">Sotho, Southern</option>
		 <option <?php if ($selected_language=="es") echo 'selected="yes"' ?> value="es">Spanish</option>
		 <option <?php if ($selected_language=="sc") echo 'selected="yes"' ?> value="sc">Sardinian</option>
		 <option <?php if ($selected_language=="sr") echo 'selected="yes"' ?> value="sr">Serbian</option>
		 <option <?php if ($selected_language=="ss") echo 'selected="yes"' ?> value="ss">Swati</option>
		 <option <?php if ($selected_language=="su") echo 'selected="yes"' ?> value="su">Sundanese</option>
		 <option <?php if ($selected_language=="sw") echo 'selected="yes"' ?> value="sw">Swahili</option>
		 <option <?php if ($selected_language=="sv") echo 'selected="yes"' ?> value="sv">Swedish</option>
		 <option <?php if ($selected_language=="ty") echo 'selected="yes"' ?> value="ty">Tahitian</option>
		 <option <?php if ($selected_language=="ta") echo 'selected="yes"' ?> value="ta">Tamil</option>
		 <option <?php if ($selected_language=="tt") echo 'selected="yes"' ?> value="tt">Tatar</option>
		 <option <?php if ($selected_language=="te") echo 'selected="yes"' ?> value="te">Telugu</option>
		 <option <?php if ($selected_language=="tg") echo 'selected="yes"' ?> value="tg">Tajik</option>
		 <option <?php if ($selected_language=="tl") echo 'selected="yes"' ?> value="tl">Tagalog</option>
		 <option <?php if ($selected_language=="th") echo 'selected="yes"' ?> value="th">Thai</option>
		 <option <?php if ($selected_language=="bo") echo 'selected="yes"' ?> value="bo">Tibetan</option>
		 <option <?php if ($selected_language=="ti") echo 'selected="yes"' ?> value="ti">Tigrinya</option>
		 <option <?php if ($selected_language=="to") echo 'selected="yes"' ?> value="to">Tonga (Tonga Islands)</option>
		 <option <?php if ($selected_language=="tn") echo 'selected="yes"' ?> value="tn">Tswana</option>
		 <option <?php if ($selected_language=="ts") echo 'selected="yes"' ?> value="ts">Tsonga</option>
		 <option <?php if ($selected_language=="tk") echo 'selected="yes"' ?> value="tk">Turkmen</option>
		 <option <?php if ($selected_language=="tr") echo 'selected="yes"' ?> value="tr">Turkish</option>
		 <option <?php if ($selected_language=="tw") echo 'selected="yes"' ?> value="tw">Twi</option>
		 <option <?php if ($selected_language=="ug") echo 'selected="yes"' ?> value="ug">Uighur</option>
		 <option <?php if ($selected_language=="uk") echo 'selected="yes"' ?> value="uk">Ukrainian</option>
		 <option <?php if ($selected_language=="ur") echo 'selected="yes"' ?> value="ur">Urdu</option>
		 <option <?php if ($selected_language=="uz") echo 'selected="yes"' ?> value="uz">Uzbek</option>
		 <option <?php if ($selected_language=="ve") echo 'selected="yes"' ?> value="ve">Venda</option>
		 <option <?php if ($selected_language=="vi") echo 'selected="yes"' ?> value="vi">Vietnamese</option>
		 <option <?php if ($selected_language=="vo") echo 'selected="yes"' ?> value="vo">Volapük</option>
		 <option <?php if ($selected_language=="cy") echo 'selected="yes"' ?> value="cy">Welsh</option>
		 <option <?php if ($selected_language=="wa") echo 'selected="yes"' ?> value="wa">Walloon</option>
		 <option <?php if ($selected_language=="wo") echo 'selected="yes"' ?> value="wo">Wolof</option>
		 <option <?php if ($selected_language=="xh") echo 'selected="yes"' ?> value="xh">Xhosa</option>
		 <option <?php if ($selected_language=="yi") echo 'selected="yes"' ?> value="yi">Yiddish</option>
		 <option <?php if ($selected_language=="yo") echo 'selected="yes"' ?> value="yo">Yoruba</option>
		 <option <?php if ($selected_language=="za") echo 'selected="yes"' ?> value="za">Zhuang</option>
		 <option <?php if ($selected_language=="zu") echo 'selected="yes"' ?> value="zu">Zulu</option>
 </select>
 </span><br/>
   <span class="bd_small"></span>
    <div style="clear:both"></div>													   
    <span class="bd_row">Delete Spam older than <span class="bd_right">days.</span>
	  <input type="text" name="bd_delete_spam_days" value="<?php echo get_option('bd_delete_spam_days')?>" class="bd_spam" />
   <br>
   <span class="bd_small"></span><br/>
    <span class="bd_row">Delete Logs older than <span class="bd_right">days.</span>
	  <input type="text" name="bd_delete_log_days" value="<?php echo get_option('bd_delete_log_days')?>" class="bd_spam" />
    <br>												   

    <span class="bd_small"></span><br>

    <span class="bd_row">Comments at posts older than <span class="bd_right"> days are spam &nbsp
	 <input onClick="javascript: document.getElementById('bd_automatic_spam_old_days').disabled =! this.checked" class="bd_automatic" type="checkbox" name="bd_automatic_spam_old_posts" value="1"   <?php echo get_option('bd_automatic_spam_old_posts')?"CHECKED":""?> /> </span>
	<input id="bd_automatic_spam_old_days" type="text" name="bd_automatic_spam_old_days" value="<?php echo get_option('bd_automatic_spam_old_days')?>" class="bd_spam" <?php echo get_option('bd_automatic_spam_old_posts')?"":"DISABLED" ?>  />
</span> 
 
<br>
    <span class="bd_small"></span>
    <div style="clear:both"></div>												   
    <span class="bd_row">Aggresivity level 
			<?php $aggresivity = get_option('bd_aggresivity_level');?>
			<select name="bd_aggresivity_level" class="bd_id">
              <option value="0" <?php echo $aggresivity==0?"SELECTED":"" ?> >Permissive</option>							
			  <option value="1" <?php echo $aggresivity==1?"SELECTED":"" ?> >Normal</option>								
		      <option value="2" <?php echo $aggresivity==2?"SELECTED":"" ?> >Aggressive</option>						
			   </select>															 
	 </span><br/>
	<p class="submit" id="bd_submit">
    <input type="submit" name="Submit" value="<?php  _e('Save Changes') ?>" />
    </p>

  </div>
  <div id="bd_table_right">
  	<span class="bd_row">Activate Cyrilic Filter 
		 <input class="bd_check" type="checkbox" name="bd_filter_cyrillic" value="1"  <?php echo get_option('bd_filter_cyrillic')?"CHECKED":""?> />
</span> <br/>
    <span class="bd_small"></span>
    <span class="bd_row">Activate Asiatic Filter 
  <input class="bd_check" type="checkbox" name="bd_filter_asiatic" value="1"   <?php echo get_option('bd_filter_asiatic')?"CHECKED":""?> />
</span> <br/>
	 <span class="bd_small"></span>
     <span class="bd_row">Moderate comments on scan error
     <input class="bd_check" type="checkbox" name="bd_moderate_on_scan_error" value="1"   <?php echo get_option('bd_moderate_on_scan_error')?"CHECKED":""?> />
	 </span> <br/>			  
    <input type="hidden" name="action" value="update" />
    <input type="hidden" name="page_options" value="bd_filter_asiatic,bd_client_id,bd_blog_language,bd_delete_log_days,bd_delete_spam_days,bd_aggresivity_level,bd_filter_cyrillic,bd_moderate_on_scan_error,bd_automatic_spam_old_posts,bd_automatic_spam_old_days"/>
	</form>
    <span class="bd_small"></span>
<?php if (!bd_multisite_network()){ ?>
  	<span class="bd_row">
	   <a href="plugins.php?page=bd_configure_dispacher&bd_page=rescan_comments">Rescan</a> existing comments.
	 </span> <br/>
    <span class="bd_small"></span>
<?php }?>
    <span class="bd_row"> Feedback </span> <br />			  
	<form method="post" action="plugins.php?page=bd_configure_dispacher&bd_page=send_feedback">
    <span class="bd_row"><textarea name="bd_feedback" rows="6" cols="30" id="bd_feedback" placeholder="Enter your comments here..."></textarea></span> <br />
    <p class="submit" id="bd_feedback_submit">
    <input type="submit" name="bd_feedback_submit" value="<?php  _e('Submit') ?>" />
    </p>
	</form>
		   										   
  </div>
</div>
</div>

</div>  
<?php
}

function bd_report_spam_comment($comment_id)
{
  global $wpdb, $bd_updating_from_rescan;
  
  if ($bd_updating_from_rescan){
	$bd_updating_from_rescan = False;
	return;
  }
  $comment_id = (int)$comment_id;
  $comment_row = $wpdb->get_row("SELECT * FROM $wpdb->comments WHERE comment_ID = '$comment_id'");
  if ( !$comment_row ) {
    return;
  }
  foreach($comment_row as $key=>$val){
    $comment[$key]=$val;
  }
  $comment['client_type'] = "blog";
  $comment['client'] = get_option('home');
  include("bdrevision.php"); 
  $comment['plugin_revision'] = $bd_revision; 
  if ($comment['comment_type'] == '')
	$comment['comment_type'] = 'comment';
  $comment['user_logged_in'] = $comment['user_id']!=0 ? 1 : 0 ;
  $rez = bd_perform("report", $comment, get_option('bd_client_id'));
  if (BD_DEBUG){
    echo "<pre>";
    print_r($comment);
    print_r($rez);
    die();
  }
}


function bd_update_ip_list($comment_id, $option_name, $method_name)
{
  $ip_list = get_option($option_name);
  $comment = get_comment($comment_id, OBJECT);
  if (!$comment)
    return;
  $ip = $comment->comment_author_IP;  
  $action="";
  if (strstr($ip_list, $ip) === FALSE){ 
	if ( $ip_list != '' && substr($ip_list, -2) != "\r\n" )
	  $ip_list .= "\r\n";
    $ip_list .= $ip."\r\n";
	$action="add";
  } else {
    $ip_list = str_replace($ip."\r\n", "",$ip_list, $count);
    if ($count==0)
      $ip_list = str_replace($ip, "",$ip_list, $count);
	$action="remove";
  }
  update_option($option_name, $ip_list);  
  $data=array();
  $data['action'] = $action;
  $data['client'] = get_option('home');
  $data['client_type'] = 'blog';
  $data['ip'] = $ip;
  include("bdrevision.php"); 
  $data['plugin_revision'] = $bd_revision;
  bd_perform($method_name, $data ,get_option('bd_client_id'));
}

function bd_update_blacklist($comment_id)
{
  bd_update_ip_list($comment_id, 'blacklist_keys', 'report_blacklist_ip');
}

function bd_update_whitelist($comment_id)
{
  bd_update_ip_list($comment_id, 'bd_whitelist_ip', 'report_whitelist_ip');
}

function bd_ip_in_whitelist($author_ip)
{	
  $whitelist = get_option('bd_whitelist_ip');	
  $ips = explode("\n", $whitelist );
  foreach ( (array) $ips as $ip)
	{
	  $ip = trim($ip);   
	  if ( empty($ip) ) { continue; }
	  $pattern = "#$ip#i";
	  if (preg_match($pattern, $author_ip))
		  return true;
	 }
  return false;    
}

function bd_comment_row_actions($actions)
{
  global $comment;
  
  $blacklist = get_option('blacklist_keys');  
  $ip = $comment->comment_author_IP;
  if ($ip == '')
	return $actions;
  if (strstr($blacklist, $ip)===FALSE){ 
	$actions['bd_blacklist_ip'] = "<a href='comment.php?action=bd_blacklist_ip&amp;c={$comment->comment_ID}' title='Blacklist IP'> Blacklist IP </a>";
  }else{
	$actions['bd_unblacklist_ip'] = "<a href='comment.php?action=bd_unblacklist_ip&amp;c={$comment->comment_ID}' title='Remove IP from Blacklist'> Remove IP from Blacklist </a>";
  }
  $whitelist = get_option('bd_whitelist_ip');
  if (strstr($whitelist, $ip)===FALSE){ 
	$actions['bd_whitelist_ip'] = "<a href='comment.php?action=bd_whitelist_ip&amp;c={$comment->comment_ID}' title='Whitelist IP'> Whitelist </a>";
  }else{
	$actions['bd_unwhitelist_ip'] = "<a href='comment.php?action=bd_unwhitelist_ip&amp;c={$comment->comment_ID}' title='Remove IP from Whitelist'> Remove from Whitelist </a>";
  }
  return $actions;
}

?>