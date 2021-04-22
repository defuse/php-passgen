<?php
    $parameters = [];

    $parameters['title'] = "Generate Passwords:\n\n";
	require_once('header.php');
    require_once('PasswordGenerator.php');

    $ascii = PasswordGenerator::getASCIIPassword(64);
    $hex = PasswordGenerator::getHexPassword(64);
    $alpha = PasswordGenerator::getAlphaNumericPassword(64);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);

    echo $ascii, "\n", $hex, "\n", $alpha, "\n", $custom, "\n";

    $number = PasswordGenerator::getRandomInts(1);

    echo $number[0], "\n";

?>
