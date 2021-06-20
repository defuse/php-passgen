<?php
    $parameters = [];

    $parameters['title'] = "Generate Passwords:$EOL$EOL";
	require_once('header.php');
    require_once('PasswordGenerator.php');

    $ascii = PasswordGenerator::getASCIIPassword(64);
    $hex = PasswordGenerator::getHexPassword(64);
    $alpha = PasswordGenerator::getAlphaNumericPassword(64);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);
    $number = PasswordGenerator::getRandomInts(1);

    echo $ascii, $EOL, $hex, $EOL, $alpha, $EOL, $custom, $EOL, $number[0], $EOL;

?>
