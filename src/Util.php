<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use function array_values;
use function count;
use Error;
use function implode;
use function pack;
use Paragon_Ie\Constant_Time\{Binary, Hex};
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Digest_Length, Invalid_Type};
use Paragon_Ie\Halite\Symmetric\Encryption_Key;
use RangeException;
use function sodium_crypto_generichash;
use const SODIUM_CRYPTO_GENERICHASH_BYTES;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MIN;
use const SODIUM_CRYPTO_GENERICHASH_KEYBYTES;
use function sodium_memzero;
use Sodium_Exception;
use function sprintf;
use function str_repeat;
use Throwable;
use TypeError;
use function unpack;
/**
 * Class Util
 *
 * Various useful utilities, used within Halite and available for general use
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
final class Util
{
    /**
     * Don't allow this to be instantiated.
     * @throws Error
     * @codeCoverageIgnore
     */
    private function __construct()
    {
        throw new Error('Do not instantiate');
    }
    /**
     * Convert a character to an integer (without cache-timing side-channels)
     *
     *
     *
     * @throws RangeException
     */
    public static function chr_to_int(string $chr): int
    {
        if (Binary::safe_strlen($chr) !== 1) {
            throw new RangeException('Must be a string with a length of 1');
        }
        $result = unpack('C', $chr);
        return (int) $result[1];
    }
    /**
     * Wrapper around sodium_crypto_generichash()
     *
     * Returns hexadecimal characters.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws SodiumException
     * @throws TypeError
     */
    public static function hash(string $input, int $length = SODIUM_CRYPTO_GENERICHASH_BYTES): string
    {
        return Hex::encode(self::raw_keyed_hash($input, '', $length));
    }
    /**
     * Wrapper around sodium_crypto_generichash()
     *
     * Returns raw binary.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws SodiumException
     */
    public static function raw_hash(string $input, int $length = SODIUM_CRYPTO_GENERICHASH_BYTES): string
    {
        return self::raw_keyed_hash($input, '', $length);
    }
    /**
     * Use a derivative of HKDF to derive multiple keys from one.
     * https://datatracker.ietf.org/doc/html/rfc5869
     *
     * This is a variant from hash_hkdf() and instead uses BLAKE2b provided by
     * libsodium.
     *
     * Important: instead of a true HKDF (from HMAC) construct, this uses the
     * crypto_generichash() key parameter. This is *probably* okay.
     *
     * @param string $ikm Initial Keying Material
     * @param int $length How many bytes?
     * @param string $info What sort of key are we deriving?
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws TypeError
     * @throws SodiumException
     */
    public static function hkdf_blake2b(string $ikm, int $length, string $info = '', string $salt = ''): string
    {
        // Sanity-check the desired output length.
        if ($length < 0 || $length > 255 * SODIUM_CRYPTO_GENERICHASH_KEYBYTES) {
            throw new Invalid_Digest_Length('Argument 2: Bad HKDF Digest Length');
        }
        // "If [salt] not provided, is set to a string of HashLen zeroes."
        if (empty($salt)) {
            // @codeCoverageIgnoreStart
            $salt = str_repeat("\x00", SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
            // @codeCoverageIgnoreEnd
        }
        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        //
        // Note: The notation used by the RFC is backwards from what we're doing here.
        // They use (Key, Msg) while our API is (Msg, Key).
        $prk = self::raw_keyed_hash($ikm, $salt);
        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        // @codeCoverageIgnoreStart
        if (Binary::safe_strlen($prk) < SODIUM_CRYPTO_GENERICHASH_KEYBYTES) {
            throw new Cannot_Perform_Operation('An unknown error has occurred');
        }
        // @codeCoverageIgnoreEnd
        // T(0) = ''
        $t = '';
        $last_block = '';
        for ($block_index = 1; Binary::safe_strlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = self::raw_keyed_hash($last_block . $info . pack('C', $block_index), $prk);
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }
        // ORM = first L octets of T
        return Binary::safe_substr($t, 0, $length);
    }
    /**
     * Convert an array of integers to a string
     *
     * @param array<int, int> $integers
     */
    public static function int_array_to_string(array $integers): string
    {
        $args = $integers;
        foreach ($args as $i => $v) {
            $args[$i] = $v & 0xff;
        }
        return pack(str_repeat('C', count($args)), ...$args);
    }
    /**
     * Convert an integer to a string (without cache-timing side-channels)
     */
    public static function int_to_chr(int $int): string
    {
        return pack('C', $int);
    }
    /**
     * Wrapper around SODIUM_CRypto_generichash()
     *
     * Expects a key (binary string).
     * Returns hexadecimal characters.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     * @throws SodiumException
     */
    public static function keyed_hash(string $input, string $key, int $length = SODIUM_CRYPTO_GENERICHASH_BYTES): string
    {
        return Hex::encode(self::raw_keyed_hash($input, $key, $length));
    }
    /**
     * Pre-authentication encoding
     *
     *
     */
    public static function PAE(string ...$pieces): string
    {
        $out = [];
        $out[] = pack('P', count($pieces));
        foreach ($pieces as $piece) {
            $out[] = pack('P', Binary::safe_strlen($piece)) . $piece;
        }
        return implode('', $out);
    }
    /**
     * Wrapper around SODIUM_CRypto_generichash()
     *
     * Expects a key (binary string).
     * Returns raw binary.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws SodiumException
     */
    public static function raw_keyed_hash(string $input, string $key, int $length = SODIUM_CRYPTO_GENERICHASH_BYTES): string
    {
        if ($length < SODIUM_CRYPTO_GENERICHASH_BYTES_MIN) {
            throw new Cannot_Perform_Operation(sprintf('Output length must be at least %d bytes.', SODIUM_CRYPTO_GENERICHASH_BYTES_MIN));
        }
        if ($length > SODIUM_CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new Cannot_Perform_Operation(sprintf('Output length must be at most %d bytes.', SODIUM_CRYPTO_GENERICHASH_BYTES_MAX));
        }
        return sodium_crypto_generichash($input, $key, $length);
    }
    /**
     * PHP 7 uses interned strings. We don't want altering this one to alter
     * the original string.
     *
     *
     *
     * @throws TypeError
     */
    public static function safe_strcpy(string $string): string
    {
        $length = Binary::safe_strlen($string);
        $return = '';
        $chunk = $length >> 1;
        if ($chunk < 1) {
            $chunk = 1;
        }
        for ($i = 0; $i < $length; $i += $chunk) {
            $return .= Binary::safe_substr($string, $i, $chunk);
        }
        return $return;
    }
    /**
     * Split a key (using HKDF-BLAKE2b instead of HKDF-HMAC-*)
     *
     *
     * @return string[]
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws SodiumException
     * @throws TypeError
     */
    public static function split_keys(Encryption_Key $master, string $salt, Config $config): array
    {
        $binary = $master->get_raw_key_material();
        /*
         * From Halite version 5, we use the HKDF info parameter instead of the salt.
         * This does two things:
         *
         * 1. It allows us to use the HKDF security definition (which is stronger than a PRF)
         * 2. It allows us to reuse the intermediary step and make key derivation faster.
         */
        if ($config->HKDF_USE_INFO) {
            $prk = self::raw_keyed_hash($binary, str_repeat("\x00", SODIUM_CRYPTO_GENERICHASH_KEYBYTES));
            $return = [self::raw_keyed_hash($config->HKDF_SBOX . $salt . "\x01", $prk), self::raw_keyed_hash($config->HKDF_AUTH . $salt . "\x01", $prk)];
            self::memzero($prk);
            return $return;
        }
        /*
         * Halite 4 and blow used this strategy:
         */
        return [Util::hkdf_blake2b($binary, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, (string) $config->HKDF_SBOX, $salt), Util::hkdf_blake2b($binary, SODIUM_CRYPTO_AUTH_KEYBYTES, (string) $config->HKDF_AUTH, $salt)];
    }
    /**
     * Turn a string into an array of integers
     *
     *
     * @return array<int, int>
     * @throws TypeError
     */
    public static function string_to_int_array(string $string): array
    {
        /**
         * @var array<int, int>
         */
        $values = array_values(unpack('C*', $string));
        return $values;
    }
    /**
     * Calculate A xor B, given two binary strings of the same length.
     *
     *
     *
     * @throws InvalidType
     */
    public static function xor_strings(string $left, string $right): string
    {
        $length = Binary::safe_strlen($left);
        if ($length !== Binary::safe_strlen($right)) {
            throw new Invalid_Type('Both strings must be the same length');
        }
        if ($length < 1) {
            return '';
        }
        return $left ^ $right;
    }
    /**
     * Wrap memzero() without breaking on sodium_compat
     *
     *
     *
     * @psalm-param-out null $var
     * @psalm-suppress UnnecessaryVarAnnotation
     * @psalm-suppress InvalidOperand
     */
    public static function memzero(string &$var): void
    {
        try {
            sodium_memzero($var);
        } catch (Throwable) {
            // Best-effort:
            $var ^= $var;
        }
        unset($var);
    }
}