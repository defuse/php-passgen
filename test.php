<?php
    function failTest($msg)
    {
        echo "FAILED: $msg\n";
        exit(1);
    }

    // Any notice, warning or deprecation is a failure. Silent notices are how
    // NUL bytes used to get into passwords unnoticed.
    function failOnError($errno, $errstr, $errfile, $errline)
    {
        if (!(error_reporting() & $errno)) {
            return false; // Suppressed with @.
        }
        failTest("PHP error $errno: $errstr at $errfile:$errline");
    }
    error_reporting(-1);
    set_error_handler('failOnError');

    // Loaded after the error handler, so notices raised while compiling the
    // library fail the tests too.
    require_once('PasswordGenerator.php');

    // Fails unless $fn throws an exception of class $class.
    function expectThrows($class, $description, $fn)
    {
        try {
            $fn();
        } catch (Exception $e) {
            if (!($e instanceof $class)) {
                failTest("$description: expected $class, got " . get_class($e) . ": " . $e->getMessage());
            }
            return;
        }
        failTest("$description: expected $class, but nothing was thrown");
    }

    // Fails unless every sample is in $allowed and each allowed value occurs
    // about equally often. The bound is 7 standard deviations, so a uniform
    // RNG fails it with probability below 10^-10 per value.
    function checkUniform($samples, $allowed, $description)
    {
        $counts = array();
        foreach ($allowed as $value) {
            $counts[$value] = 0;
        }
        foreach ($samples as $sample) {
            if (!in_array($sample, $allowed, true)) {
                failTest("$description: produced " . var_export($sample, true) . ", which isn't allowed.");
            }
            $counts[$sample]++;
        }
        $n = count($samples);
        $p = 1 / count($allowed);
        $expected = $n * $p;
        $bound = 7 * sqrt($n * $p * (1 - $p));
        foreach ($counts as $value => $count) {
            if (abs($count - $expected) > $bound) {
                failTest("$description: " . var_export($value, true) . " occurred $count times; expected about " . round($expected) . ".");
            }
        }
    }

    function describe($value)
    {
        return str_replace("\n", "", var_export($value, true));
    }

    $MIN_INT = -PHP_INT_MAX - 1; // PHP_INT_MIN only exists in PHP 7+.

    echo "Sample Passwords:\n\n";
    $ascii = PasswordGenerator::getASCIIPassword(64);
    $hex = PasswordGenerator::getHexPassword(64);
    $alpha = PasswordGenerator::getAlphaNumericPassword(64);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), 64);
    echo $ascii, "\n", $hex, "\n", $alpha, "\n", $custom, "\n\n";

    // Passwords have the right length and characters, and don't repeat.
    $last = array();
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
    }

    // Every character of each set appears, about equally often.
    $asciiSet = str_split("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");
    $alnumSet = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    $hexSet = str_split("0123456789ABCDEF");
    checkUniform(str_split(PasswordGenerator::getASCIIPassword(20000)), $asciiSet, "ASCII");
    checkUniform(str_split(PasswordGenerator::getAlphaNumericPassword(20000)), $alnumSet, "AlphaNumeric");
    checkUniform(str_split(PasswordGenerator::getHexPassword(20000)), $hexSet, "Hex");
    checkUniform(str_split(PasswordGenerator::getCustomPassword(array('a', 'b'), 20000)), array('a', 'b'), "Custom");

    // Character sets whose keys aren't 0..n-1 are re-indexed, not misread as
    // containing NUL bytes.
    $noLookalikes = array_diff($alnumSet, array('0', 'O', 'o', '1', 'l', 'I'));
    checkUniform(str_split(PasswordGenerator::getCustomPassword($noLookalikes, 20000)), array_values($noLookalikes), "array_diff() set");
    $assoc = array('x' => 'p', 'y' => 'q', 'z' => 'r');
    checkUniform(str_split(PasswordGenerator::getCustomPassword($assoc, 20000)), array('p', 'q', 'r'), "Associative set");
    $bytes = array("\x00", "\x80", "\xFF");
    checkUniform(str_split(PasswordGenerator::getCustomPassword($bytes, 20000)), $bytes, "Non-ASCII single-byte set");

    // Invalid lengths throw, for every password function.
    $badLengths = array(0, -1, 16.0, "16", null, true, false, array());
    foreach ($badLengths as $length) {
        foreach (array('getASCIIPassword', 'getAlphaNumericPassword', 'getHexPassword') as $func) {
            expectThrows('InvalidArgumentException', "$func(" . describe($length) . ")", function () use ($func, $length) {
                call_user_func(array('PasswordGenerator', $func), $length);
            });
        }
        expectThrows('InvalidArgumentException', "getCustomPassword(set, " . describe($length) . ")", function () use ($length) {
            PasswordGenerator::getCustomPassword(array('a', 'b'), $length);
        });
    }

    // Invalid character sets throw instead of silently giving weak passwords.
    $badSets = array(
        'a string instead of an array' => "abcdef",
        'an empty array' => array(),
        'a single character' => array('a'),
        'duplicates' => array('a', 'b', 'a'),
        'a word list' => array('apple', 'banana', 'cherry', 'date'),
        'multi-byte UTF-8 characters' => array("\xC3\xA4", "\xC3\xB6", "\xC3\xBC", "\xC3\x9F"), // ä ö ü ß
        'single-byte and multi-byte characters' => array('a', 'b', "\xC3\xA4"),
        'ints' => range(0, 9),
        'an empty string' => array('', 'a', 'b'),
        'null' => array(null, 'a', 'b'),
        'a nested array' => array(array('a'), 'b', 'c'),
        'null instead of an array' => null,
    );
    foreach ($badSets as $description => $set) {
        expectThrows('InvalidArgumentException', "Character set with $description", function () use ($set) {
            PasswordGenerator::getCustomPassword($set, 16);
        });
    }

    // getRandomInt(): only values in range, all of them, about equally often.
    if (PasswordGenerator::getRandomInt(5, 5) !== 5) {
        failTest("getRandomInt(5, 5) isn't 5.");
    }
    foreach (array(array(1, 6), array(-3, 3), array(0, 1), array(-10, -8)) as $r) {
        $samples = array();
        for ($i = 0; $i < 3000; $i++) {
            $samples[] = PasswordGenerator::getRandomInt($r[0], $r[1]);
        }
        checkUniform($samples, range($r[0], $r[1]), "getRandomInt({$r[0]}, {$r[1]})");
    }

    // The widest allowed ranges work.
    $wideRanges = array(array(0, PHP_INT_MAX), array($MIN_INT, -1), array(-1000, PHP_INT_MAX - 1000));
    foreach ($wideRanges as $r) {
        for ($i = 0; $i < 100; $i++) {
            $n = PasswordGenerator::getRandomInt($r[0], $r[1]);
            if (!is_int($n) || $n < $r[0] || $n > $r[1]) {
                failTest("getRandomInt({$r[0]}, {$r[1]}) returned " . describe($n) . ".");
            }
        }
    }

    // Invalid bounds throw, including ranges too wide to cover uniformly
    // (which used to loop forever).
    $badRanges = array(
        'min > max' => array(2, 1),
        'float bounds' => array(0.5, 3.7),
        'whole-number float bounds' => array(1.0, 6.0),
        'numeric strings' => array("1", "6"),
        'non-numeric strings' => array("abc", 0),
        'null' => array(null, 6),
        'INF' => array(0, INF),
        'NAN' => array(0, NAN),
        'the full int range' => array($MIN_INT, PHP_INT_MAX),
        'a range of PHP_INT_MAX + 1' => array(-1, PHP_INT_MAX),
        'a negative range of PHP_INT_MAX + 1' => array($MIN_INT, 0),
    );
    foreach ($badRanges as $description => $r) {
        expectThrows('InvalidArgumentException', "getRandomInt() with $description", function () use ($r) {
            PasswordGenerator::getRandomInt($r[0], $r[1]);
        });
    }

    // getRandomInts(): the right number of ints, all in range.
    for ($i = 0; $i < 1000; $i++) {
        $ints = PasswordGenerator::getRandomInts($i);
        $count = count($ints);
        if ($count != $i) {
            failTest("$i random ints is $count and not $i");
        }
        foreach ($ints as $n) {
            if (!is_int($n) || $n < 0) {
                failTest("getRandomInts() returned " . describe($n) . ".");
            }
        }
    }
    foreach (array(2.0, "2", null, PHP_INT_MAX) as $n) {
        expectThrows('InvalidArgumentException', "getRandomInts(" . describe($n) . ")", function () use ($n) {
            PasswordGenerator::getRandomInts($n);
        });
    }

    echo "ALL TESTS PASS!\n";
    exit(0);
