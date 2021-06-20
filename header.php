<?php
    if(php_sapi_name()=='cli') {
        $EOL = "\n";
    } else {
        $EOL = '<br>';
    }
	require_once('PasswordGenerator.php');
