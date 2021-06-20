<?php
    $parameters = [];

	require_once('header.php');
    $parameters['title'] = "Generate Passwords:$EOL$EOL";
    echo $parameters['title'];

    $ascii = PasswordGenerator::getASCIIPassword(64);
    $hex = PasswordGenerator::getHexPassword(64);
    $alpha = PasswordGenerator::getAlphaNumericPassword(64);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);
    $number = PasswordGenerator::getRandomInts(1);

    if($EOL == '<br>') {
        echo '<div style="font-family: monospace">';
    }
    echo $ascii, $EOL, $hex, $EOL, $alpha, $EOL, $custom, $EOL, $number[0], $EOL;
    if($EOL == '<br>') {
        echo '</div>';
    }
?>
