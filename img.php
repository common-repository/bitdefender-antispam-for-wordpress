<?php
session_start();
$_SESSION['bd_session']['img_loaded'] = 1;
header("Content-Type: image/gif");
echo base64_decode("R0lGODlhAQABALMAAP8p9////////////////////////////////////////////////////////////yH5BAEAAAAALAAAAAABAAEAAAQCEEQAOw==");
?>