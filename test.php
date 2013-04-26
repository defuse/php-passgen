<?php
    require_once('PasswordGenerator.php');
    $ascii = PasswordGenerator::getASCIIPassword(64);
    $hex = PasswordGenerator::getHexPassword(64);
    $alpha = PasswordGenerator::getAlphaNumericPassword(64);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);
    echo $ascii, "\n", $hex, "\n", $alpha, "\n", $custom, "\n";

    echo "\n\n\n";

    echo "ASCII:\n";
    echo PasswordGenerator::getASCIIPassword(64), "\n";
    echo PasswordGenerator::getASCIIPassword(64), "\n";
    echo PasswordGenerator::getASCIIPassword(64), "\n";
    echo PasswordGenerator::getASCIIPassword(64), "\n";
    echo PasswordGenerator::getASCIIPassword(64), "\n";
    echo PasswordGenerator::getASCIIPassword(64), "\n";
    echo "Alphanumeric:\n";
    echo PasswordGenerator::getAlphaNumericPassword(64), "\n";
    echo PasswordGenerator::getAlphaNumericPassword(64), "\n";
    echo PasswordGenerator::getAlphaNumericPassword(64), "\n";
    echo PasswordGenerator::getAlphaNumericPassword(64), "\n";
    echo PasswordGenerator::getAlphaNumericPassword(64), "\n";
    echo "Hex:\n";
    echo PasswordGenerator::getHexPassword(64), "\n";
    echo PasswordGenerator::getHexPassword(64), "\n";
    echo PasswordGenerator::getHexPassword(64), "\n";
    echo PasswordGenerator::getHexPassword(64), "\n";
    echo PasswordGenerator::getHexPassword(64), "\n";
    echo PasswordGenerator::getHexPassword(64), "\n";
    echo "Custom (a,b):\n";
    echo PasswordGenerator::getCustomPassword(array("a","b"), 64), "\n";
    echo "Improper usage:\n";
    echo PasswordGenerator::getCustomPassword("abc", 64), "\n";
?>
