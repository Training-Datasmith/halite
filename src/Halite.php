<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use Error;
use function extension_loaded;
use function implode;
use Paragon_Ie\Constant_Time\{Base32, Base32Hex, Base64, Base64url_Safe, Hex};
use Paragon_Ie\Halite\Alerts\Invalid_Type;
use const SODIUM_LIBRARY_MAJOR_VERSION;
use const SODIUM_LIBRARY_VERSION;
/**
 * Class Halite
 *
 * This is just an final class that hosts some constants
 *
 * Version Tag Info:
 *
 *  \x31\x41 => 3.141 (approx. pi)
 *  \x31\x42 => 3.142 (approx. pi)
 *  Because pi is the symbol we use for Paragon Initiative Enterprises
 *  \x00\x07 => version 0.07
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Halite
{
    public const VERSION = '5.0.0';
    public const HALITE_VERSION_KEYS = "1@\x05\x00";
    public const HALITE_VERSION_FILE = "1A\x05\x00";
    public const HALITE_VERSION = "1B\x05\x00";
    /* Raw bytes (decoded) of the underlying ciphertext */
    public const VERSION_TAG_LEN = 4;
    public const VERSION_PREFIX = 'MUIFA';
    public const VERSION_OLD_PREFIX = 'MUIEA';
    public const ENCODE_HEX = 'hex';
    public const ENCODE_BASE32 = 'base32';
    public const ENCODE_BASE32HEX = 'base32hex';
    public const ENCODE_BASE64 = 'base64';
    public const ENCODE_BASE64URLSAFE = 'base64urlsafe';
    /**
     * Don't allow this to be instantiated.
     *
     * @throws Error
     * @codeCoverageIgnore
     */
    private function __construct()
    {
        throw new Error('Do not instantiate');
    }
    /**
     * Select which encoding/decoding function to use.
     *
     * @internal
     * @return ?callable
     *
     * @throws InvalidType
     * @psalm-suppress InvalidReturnStatement
     * @psalm-suppress InvalidReturnType
     */
    public static function choose_encoder(string|bool $chosen, bool $decode = false): ?string
    {
        if ($chosen === true) {
            return null;
        }
        if ($chosen === false) {
            return implode('::', [Hex::class, $decode ? 'decode' : 'encode']);
        }
        if ($chosen === self::ENCODE_BASE32) {
            return implode('::', [Base32::class, $decode ? 'decode' : 'encode']);
        }
        if ($chosen === self::ENCODE_BASE32HEX) {
            return implode('::', [Base32Hex::class, $decode ? 'decode' : 'encode']);
        }
        if ($chosen === self::ENCODE_BASE64) {
            return implode('::', [Base64::class, $decode ? 'decode' : 'encode']);
        }
        if ($chosen === self::ENCODE_BASE64URLSAFE) {
            return implode('::', [Base64url_Safe::class, $decode ? 'decode' : 'encode']);
        }
        if ($chosen === self::ENCODE_HEX) {
            return implode('::', [Hex::class, $decode ? 'decode' : 'encode']);
        }
        throw new Invalid_Type('Illegal value for encoding choice.');
    }
    /**
     * Is Libsodium set up correctly? Use this to verify that you can use the
     * newer versions of Halite correctly.
     *
     * @codeCoverageIgnore
     */
    public static function is_libsodium_setup_correctly(bool $echo = false): bool
    {
        if (!extension_loaded('sodium')) {
            if ($echo) {
                echo "You do not have the sodium extension enabled.\n";
            }
            return false;
        }
        // Require libsodium 1.0.15
        $major = SODIUM_LIBRARY_MAJOR_VERSION;
        if ($major < 10) {
            if ($echo) {
                echo 'Halite needs libsodium 1.0.15 or higher. You have: ', SODIUM_LIBRARY_VERSION, "\n";
            }
            return false;
        }
        return true;
    }
}