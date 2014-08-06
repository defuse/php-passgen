<?php
    require_once('PasswordGenerator.php');
    echo "Sample Passwords:\n\n";
    $ascii = PasswordGenerator::getASCIIPassword(64);
    $hex = PasswordGenerator::getHexPassword(64);
    $alpha = PasswordGenerator::getAlphaNumericPassword(64);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);
    echo $ascii, "\n", $hex, "\n", $alpha, "\n", $custom, "\n\n";

    function failTest($msg)
    {
        echo "FAILED: $msg\n";
        exit(1);
    }

    $last = array();
    $ascii_chars = array();
    $alpha_chars = array();
    $hex_chars = array();
    $custom_chars = array();
    for ($i = 0; $i < 20; $i++) {
        $ascii = PasswordGenerator::getASCIIPassword(64);
        $alpha = PasswordGenerator::getAlphaNumericPassword(64);
        $hex = PasswordGenerator::getHexPassword(64);
        $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);

        if (in_array($ascii, $last)) {
            failTest("Duplicate ASCII password.");
        }

        if (in_array($alpha, $last)) {
            failTest("Duplicate AlphaNumeric password.");
        }

        if (in_array($hex, $last)) {
            failTest("Duplicate Hex password.");
        }

        if (in_array($custom, $last)) {
            failTest("Duplicate Custom password.");
        }

        if (preg_match("/^[!-~]{64}$/", $ascii) !== 1) {
            failTest("ASCII regexp failed.");
        }

        if (preg_match("/^[a-zA-Z0-9]{64}$/", $alpha) !== 1) {
            failTest("AlphaNumeric regexp failed.");
        }

        if (preg_match("/^[0-9A-F]{64}$/", $hex) !== 1) {
            failTest("Hex regexp failed.");
        }

        if (preg_match("/^[ab]{64}$/", $custom) !== 1) {
            failTest("Custom regexp failed.");
        }

        $last[] = $ascii;
        $last[] = $alpha;
        $last[] = $hex;
        $last[] = $custom;

        $ascii_chars = array_merge($ascii_chars, str_split($ascii));
        $alpha_chars = array_merge($alpha_chars, str_split($alpha));
        $hex_chars = array_merge($hex_chars, str_split($hex));
        $custom_chars = array_merge($custom_chars, str_split($custom));
    }

    $ascii_chars = array_unique($ascii_chars);
    $alpha_chars = array_unique($alpha_chars);
    $hex_chars = array_unique($hex_chars);
    $custom_chars = array_unique($custom_chars);

    if (count($ascii_chars) !== 94) {
        failTest("Not all ASCII chars are included.");
    }

    if (count($alpha_chars) !== 62) {
        failTest("Not all AlphaNumeric chars are included.");
    }

    if (count($hex_chars) !== 16) {
        failTest("Not all Hex chars are included.");
    }

    if (count($custom_chars) !== 2) {
        failTest("Not all Custom chars are included.");
    }

    if (PasswordGenerator::getCustomPassword("abc", 64) !== false) {
        failTest("Improper usage does not return false.");
    }

    for ($i = 0; $i < 1000; $i++) {
        $ints = PasswordGenerator::getRandomInts($i);
        $count = count($ints);
        if ($count != $i) {
            failTest("$i random ints is $count and not $i");
        }
    }
        

    echo "ALL TESTS PASS!\n";
    exit(0);

?>
