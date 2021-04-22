<?php
	require_once('PasswordGenerator.php');
    echo $parameters['title'];
    $ascii = PasswordGenerator::getASCIIPassword(64);
    $hex = PasswordGenerator::getHexPassword(64);
    $alpha = PasswordGenerator::getAlphaNumericPassword(64);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);
    echo $ascii, "\n", $hex, "\n", $alpha, "\n", $custom, "\n\n";
