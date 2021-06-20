<?php
    $parameters = [];

	require_once('header.php');
    $parameters['title'] = "Generate Passwords:$EOL$EOL";
    echo $parameters['title'];

    $len = 64;
    $ascii = PasswordGenerator::getASCIIPassword($len);
    $hex = PasswordGenerator::getHexPassword($len);
    $alpha = PasswordGenerator::getAlphaNumericPassword($len);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), $len);
    $number = PasswordGenerator::getRandomInts(1);

    if($EOL == '<br>')
    {
        echo 'len: 64';
        echo '<div style="font-family: monospace">';
        echo 'ASCII', $EOL, $ascii, $EOL, $EOL, 'Hex', $EOL, $hex, $EOL, $EOL, 
            'AlphaNumeric', $EOL, $alpha, $EOL, $EOL, 'Custom', $EOL, $custom, $EOL, $EOL, 
            'Numeric', $EOL, $number[0], $EOL;
    }
    else {
        echo $ascii, $EOL, $hex, $EOL, $alpha, $EOL, $custom, $EOL, $number[0], $EOL;
    }
    if($EOL == '<br>') {
        echo '</div>';
    }
?>
