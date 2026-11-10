<?php

/*
 * Unbiased random password generator.
 * Copyright (c) 2015, Taylor Hornby
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

class ExtremelyUnlikelyRandomnessException extends Exception {}
class RandomSourceFailureException extends Exception {}

class PasswordGenerator
{
    public static function getASCIIPassword($length)
    {
        $printable = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
        return self::getCustomPassword(str_split($printable), $length);
    }

    public static function getAlphaNumericPassword($length)
    {
        $alphanum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        return self::getCustomPassword(str_split($alphanum), $length);
    }

    public static function getHexPassword($length)
    {
        $hex = "0123456789ABCDEF";
        return self::getCustomPassword(str_split($hex), $length);
    }

    /*
     * Create a random password from a custom character set.
     * $characterSet - An array of at least 2 distinct single-byte strings, such
     *                 as str_split("abc123"). Its keys are ignored. Multi-byte
     *                 characters (like UTF-8 "ä") and multi-character elements
     *                 (like words) are rejected.
     * $length - The number of characters in the password, as a positive int.
     * Throws InvalidArgumentException if an argument breaks these rules, and
     * RandomSourceFailureException if no secure random source is available.
     * It never returns a weaker password than the arguments ask for.
     */
    public static function getCustomPassword($characterSet, $length)
    {
        if (!is_int($length) || $length < 1) {
            throw new InvalidArgumentException("Password length must be a positive int.");
        }
        if (!is_array($characterSet)) {
            throw new InvalidArgumentException("Character set must be an array of single-byte strings.");
        }

        // Re-index so the keys are 0..n-1 whatever keys the caller's array has
        // (e.g. after array_diff() or array_filter()). The lookup below reads
        // keys 0..n-1, so other keys would turn into NUL bytes.
        $characterSet = array_values($characterSet);
        $charSetLen = count($characterSet);

        // Each element must be exactly one byte. The lookup below copies one
        // byte per element, and $length counts bytes, so anything longer would
        // be silently truncated (giving far weaker passwords) or miscounted.
        foreach ($characterSet as $i => $element) {
            if (!is_string($element) || self::safeStrlen($element) !== 1) {
                throw new InvalidArgumentException(
                    "Character set element $i is not a single-byte string. Multi-byte " .
                    "characters and multi-character elements (such as words) are not supported."
                );
            }
        }
        if ($charSetLen < 2) {
            throw new InvalidArgumentException("Character set must contain at least 2 characters.");
        }
        if (count(array_unique($characterSet)) !== $charSetLen) {
            throw new InvalidArgumentException(
                "Character set contains duplicates, which would make some characters more likely than others."
            );
        }

        $random = self::getRandomInts($length * 2);
        $mask = self::getMinimalBitMask($charSetLen - 1); 

        $password = "";

        // To generate the password, we repeatedly try random integers and use the ones within the range
        // 0 to $charSetLen - 1 to select an index into the character set. This is the only known way to
        // make a truly unbiased random selection from a set using random binary data.

        // A poorly implemented or malicious RNG could cause an infinite loop, leading to a denial of service.
        // We need to guarantee termination, so $iterLimit holds the number of further iterations we will allow.
        // It is extremely unlikely (about 2^-64) that more than $length*64 random ints are needed.
        $iterLimit = max($length, $length * 64);   // If length is close to PHP_INT_MAX we don't want to overflow.
        $randIdx = 0;
        while(self::safeStrlen($password) < $length)
        {
            if($randIdx >= count($random))
            {
                $random = self::getRandomInts(2*($length - self::safeStrlen($password)));
                $randIdx = 0;
            }

            // This is wasteful, but RNGs are fast and doing otherwise adds complexity and bias.
            $c = $random[$randIdx++] & $mask;
            // Only use the random number if it is in range, otherwise try another (next iteration).
            if($c < $charSetLen) {
                $picked = self::sidechannel_safe_array_index($characterSet, $c);
                if ($picked === false) {
                    // Unreachable with a validated set and an in-range index.
                    throw new LogicException("Character lookup failed.");
                }
                $password .= $picked;
            }

            // Guarantee termination
            $iterLimit--;
            if($iterLimit <= 0) {
                throw new ExtremelyUnlikelyRandomnessException("Hit iteration limit when generating password.");
            }
        }

        return $password;
    }

    // Returns a uniformly random int from $min_inclusive to $max_inclusive.
    // Both bounds must be ints, and $max_inclusive - $min_inclusive can be at
    // most PHP_INT_MAX. Throws InvalidArgumentException otherwise.
    public static function getRandomInt($min_inclusive, $max_inclusive)
    {
        if (!is_int($min_inclusive) || !is_int($max_inclusive)) {
            throw new InvalidArgumentException("min and max must be ints.");
        }
        if ($min_inclusive > $max_inclusive) {
            throw new InvalidArgumentException("min is greater than max.");
        }
        if ($min_inclusive === $max_inclusive) {
            return $min_inclusive;
        }

        // PHP ints overflow to floats, so a range wider than PHP_INT_MAX shows
        // up here as a non-int. Each random int has only PHP_INT_MAX + 1
        // possible values, so a wider range couldn't be covered uniformly.
        $range = $max_inclusive - $min_inclusive;
        if (!is_int($range)) {
            throw new InvalidArgumentException("max - min must be at most PHP_INT_MAX.");
        }
        $mask = self::getMinimalBitMask($range);

        $random = self::getRandomInts(10);
        $randIdx = 0;

        $iterLimit = 100;
        while (1) {
            /* Replenish the random integers if we ran out. */
            if ($randIdx >= count($random)) {
                $random = self::getRandomInts(10);
                $randIdx = 0;
            }

            $offset = $random[$randIdx++] & $mask;
            if ($offset <= $range) {
                return $min_inclusive + $offset;
            }

            $iterLimit--;
            if ($iterLimit <= 0) {
                throw new ExtremelyUnlikelyRandomnessException("Hit iteration limit when generating random integer.");
            }
        }
    }

    // Returns $set[$index] without branching on $index or using it as an array
    // index, so the choice doesn't leak through timing. $set must be a list
    // (keys 0..n-1) of single-byte strings, as getCustomPassword() guarantees.
    // Returns false if $set is too large or $index is out of range.
    private static function sidechannel_safe_array_index($set, $index)
    {
        // The mask trick below is only correct when $i ^ $index fits in 16
        // bits, which these bounds guarantee.
        $count = count($set);
        if ($count > 65535 || $index < 0 || $index >= $count) {
            return false;
        }
        $character = 0;
        for ($i = 0; $i < $count; $i++) {
            $x = $i ^ $index;
            $mask = (((($x | ($x >> 16)) & 0xFFFF) + 0xFFFF) >> 16) - 1;
            $character |= ord($set[$i]) & $mask;
        }
        return chr($character);
    }

    // Returns the smallest bit mask of all 1s such that ($toRepresent & mask) = $toRepresent.
    // $toRepresent must be an int greater than or equal to 1.
    private static function getMinimalBitMask($toRepresent)
    {
        // The int check guarantees the loop ends: no int exceeds PHP_INT_MAX,
        // which is itself all 1s. (With a float it could loop forever.)
        if (!is_int($toRepresent) || $toRepresent < 1) {
            throw new InvalidArgumentException("getMinimalBitMask() needs a positive int.");
        }
        $mask = 0x1;
        while($mask < $toRepresent) {
            $mask = ($mask << 1) | 1;
        }
        return $mask;
    }

    // Returns an array of $numInts random integers between 0 and PHP_INT_MAX
    // (an empty array if $numInts <= 0). $numInts must be an int.
    public static function getRandomInts($numInts)
    {
        if (!is_int($numInts)) {
            throw new InvalidArgumentException("Number of random ints must be an int.");
        }
        $ints = array();
        if ($numInts <= 0) {
            return $ints;
        }
        $numBytes = $numInts * PHP_INT_SIZE;
        if (!is_int($numBytes)) {
            // The multiplication overflowed to a float.
            throw new InvalidArgumentException("Too many random ints requested.");
        }
        self::selfTestRandomSource();
        $rawBinary = self::getRandomBytes($numBytes);
        for($i = 0; $i < $numInts; ++$i)
        {
            $thisInt = 0;
            for($j = 0; $j < PHP_INT_SIZE; ++$j)
            {
                $thisInt = ($thisInt << 8) | (ord($rawBinary[$i * PHP_INT_SIZE + $j]) & 0xFF);
            }
            // Clear the sign bit, leaving a uniform value from 0 to PHP_INT_MAX.
            $thisInt = $thisInt & PHP_INT_MAX;
            $ints[] = $thisInt;
        }
        return $ints;
    }

    // Returns a string of $numBytes bytes from the operating system's CSPRNG.
    // Uses PHP 7's native random_bytes(), falling back to ext-mcrypt's
    // mcrypt_create_iv() with MCRYPT_DEV_URANDOM on PHP 5. There is no other
    // fallback: if neither is available, or the read fails or comes up short,
    // this throws RandomSourceFailureException rather than return anything.
    // $numBytes must be a positive integer.
    private static function getRandomBytes($numBytes)
    {
        if (self::isNativeFunction('random_bytes')) {
            try {
                $bytes = random_bytes($numBytes);
            } catch (Exception $e) {
                throw new RandomSourceFailureException(
                    "random_bytes() failed: " . $e->getMessage(), 0, $e
                );
            }
        } elseif (self::isNativeFunction('mcrypt_create_iv')) {
            // Unlike random_bytes(), mcrypt_create_iv() never checks that
            // /dev/urandom really is a device: if it's a regular file (say, in
            // a badly built chroot) it returns that file's contents. So insist
            // on a character device ourselves. stat() follows symlinks, which
            // matters on e.g. Solaris. On Windows mcrypt uses CryptGenRandom.
            if (DIRECTORY_SEPARATOR !== '\\') {
                $st = @stat('/dev/urandom');
                if ($st === false || ($st['mode'] & 0170000) !== 0020000) {
                    throw new RandomSourceFailureException(
                        "/dev/urandom is missing, isn't a character device, or can't be " .
                        "checked: open_basedir (if set) must include /dev/urandom, and on " .
                        "PHP 5.3 safe_mode must be off."
                    );
                }
                // On Linux, also insist on the kernel's random devices (1:9 is
                // /dev/urandom, 1:8 is /dev/random). Another character device
                // mounted there, like /dev/zero, would give constant output,
                // and /dev/null would make PHP 5's mcrypt loop forever.
                if (PHP_OS === 'Linux' && $st['rdev'] !== 265 && $st['rdev'] !== 264) {
                    throw new RandomSourceFailureException(
                        "/dev/urandom isn't the kernel's random device."
                    );
                }
            }
            // On failure this returns false, so the check below is what keeps a
            // failed read from becoming all-zero "random" data. The @ stops its
            // warning from reaching error handlers that turn warnings into
            // exceptions, so the failure surfaces as RandomSourceFailureException.
            $bytes = @mcrypt_create_iv($numBytes, MCRYPT_DEV_URANDOM);
        } else {
            throw new RandomSourceFailureException(
                "No secure random source available: random_bytes() is missing " .
                "or disabled, and the mcrypt extension isn't loaded."
            );
        }

        if (!is_string($bytes) || self::safeStrlen($bytes) !== $numBytes) {
            throw new RandomSourceFailureException(
                "Could not read enough random bytes from the system RNG."
            );
        }
        return $bytes;
    }

    // Checks, once per process, that the random source isn't obviously broken
    // before any of its output is used. A character device that isn't random,
    // like /dev/zero mounted over /dev/urandom, passes every other check. The
    // Linux device check in getRandomBytes() catches that for mcrypt, but
    // random_bytes() also reads /dev/urandom when getrandom() isn't available
    // (e.g. Linux before 3.17), and PHP only checks that it's a character
    // device. Two 32-byte reads that are all zeros, or identical to each
    // other, mean the source is broken; a real RNG does that with probability
    // around 2^-255. Throws RandomSourceFailureException.
    private static function selfTestRandomSource()
    {
        static $passed = false;
        if ($passed) {
            return;
        }
        $zeros = str_repeat("\0", 32);
        $first = self::getRandomBytes(32);
        $second = self::getRandomBytes(32);
        if ($first === $zeros || $second === $zeros || $first === $second) {
            throw new RandomSourceFailureException(
                "The system RNG failed a self-test (it returned all zeros, or the " .
                "same bytes twice), so it can't be trusted."
            );
        }
        $passed = true;
    }

    // True only for functions compiled into PHP or an extension. A userland
    // function of the same name (e.g. a polyfill built on mt_rand()) can't be
    // trusted to be cryptographically secure, so it is never used.
    private static function isNativeFunction($name)
    {
        if (!function_exists($name)) {
            return false;
        }
        $reflection = new ReflectionFunction($name);
        return $reflection->isInternal();
    }

    // Returns the length of $str in bytes. With mbstring.func_overload (PHP < 8)
    // strlen() can count characters instead; mb_strlen() with '8bit' can't. A
    // userland mb_strlen() (e.g. a polyfill) isn't trusted, but then mbstring
    // isn't loaded, so nothing can have overloaded strlen() either.
    public static function safeStrlen($str)
    {
        static $useMbStrlen = null;
        if ($useMbStrlen === null) {
            $useMbStrlen = self::isNativeFunction('mb_strlen');
        }
        if ($useMbStrlen) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }

}
