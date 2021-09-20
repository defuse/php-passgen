<style>
	@import url('https://fonts.googleapis.com/css2?family=Open+Sans&display=swap');
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
