php-passgen
============

[![Build Status](https://travis-ci.org/defuse/php-passgen.svg?branch=master)](https://travis-ci.org/defuse/php-passgen)

A MIT-licensed library for generating cryptographically secure passwords in PHP.

**Deprecated: don't use this library in new code.** It is no longer maintained.
Earlier versions have bugs that can silently produce weak passwords (see
[PR #18](https://github.com/defuse/php-passgen/pull/18)). This release fixes
the known ones for existing users, but you should move to PHP's built-in
functions instead:

- PHP 8.3+: `(new \Random\Randomizer())->getBytesFromString($characters, $length)`
- PHP 7+: pick each character with `$characters[random_int(0, strlen($characters) - 1)]`
- PHP 5: the same, with [paragonie/random_compat](https://github.com/paragonie/random_compat)
  providing `random_int()`

All of these pick bytes, not characters, and nothing checks the input for you:
`$characters` must be distinct single-byte (ASCII) characters. A multi-byte
character like UTF-8 `"ä"` gets split into its separate bytes, and a duplicated
character is picked more often. Also create the `Randomizer` with no engine
argument, so it uses the secure default (`Random\Engine\Secure`): engines like
`Random\Engine\Mt19937` are seedable and predictable.

Requirements
------------

PHP 7 or later, or PHP 5.3 or later with the mcrypt extension. Randomness comes
only from PHP 7's built-in `random_bytes()` or, without it (on PHP 5, or on PHP
7.0/7.1 with `random_bytes` disabled), from mcrypt reading `/dev/urandom`
(CryptGenRandom on Windows). There is no weaker fallback.

When mcrypt is used, `open_basedir` (if set) must include `/dev/urandom`, and
on PHP 5.3 `safe_mode` must be off. Otherwise every call throws
`RandomSourceFailureException`.

Usage
-----

```php
require_once 'PasswordGenerator.php';

$password = PasswordGenerator::getASCIIPassword(20);        // printable ASCII
$password = PasswordGenerator::getAlphaNumericPassword(20); // A-Z, a-z, 0-9
$password = PasswordGenerator::getHexPassword(32);          // 0-9, A-F
$password = PasswordGenerator::getCustomPassword(str_split('abcdef123'), 16);
$roll     = PasswordGenerator::getRandomInt(1, 6);          // 1 to 6 inclusive
```

Lengths must be positive ints: `16.0` and `"16"` are rejected.

A custom character set must be an array of at least 2 distinct single-byte
strings. Its keys don't matter, so the result of `array_diff()` is fine.
Multi-byte characters (such as UTF-8 `"ä"`) and multi-character elements (such
as words) are rejected, because the library generates passwords from
characters, not words.

`getRandomInt()` needs int bounds with `$max - $min` at most `PHP_INT_MAX`.

Errors are reported with exceptions, never with return values:

- `InvalidArgumentException`: an argument breaks the rules above.
- `RandomSourceFailureException`: no secure random source is available, or it
  failed.
- `ExtremelyUnlikelyRandomnessException`: an iteration limit was hit, which
  only a broken random source should ever cause.

Audit Status
-------------

Although it has been developed with security as the top priority, and with
secure coding practices in mind, this code has not received any professional
review.
