<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inconsolata&display=swap" rel="stylesheet"> 
<style>
body {
    font-family: 'Inconsolata', monospace;
}
</style>
<?php
    if(php_sapi_name() == 'cli') {
        $EOL = "\n";
    } else {
        $EOL = '<br>';
    }
	require_once('PasswordGenerator.php');
