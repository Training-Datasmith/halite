<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Symmetric;

use Error;
use function hash_equals;
use function is_callable;
use function is_null;
use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\{Halite, Symmetric\Config as SymmetricConfig, Util};
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Digest_Length, Invalid_Message, Invalid_Signature, Invalid_Type};
use Paragon_Ie\Hidden_String\Hidden_String;
use function random_bytes;
use RangeException;
use function sodium_crypto_generichash;
use const SODIUM_CRYPTO_STREAM_NONCEBYTES;
use function sodium_crypto_stream_xchacha20_xor;
use function sodium_crypto_stream_xor;
use Sodium_Exception;
use Throwable;
use TypeError;
/**
 * Class Crypto
 *
 * Encapsulates symmetric-key cryptography
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Symmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Crypto
{
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
     * Authenticate a string
     *
     *
     *
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function authenticate(string $message, Authentication_Key $secret_key, bool|string $encoding = Halite::ENCODE_BASE64URLSAFE): string
    {
        $config = Symmetric_Config::get_config(Halite::HALITE_VERSION, 'auth');
        $mac = self::calculate_mac($message, $secret_key->get_raw_key_material(), $config);
        $encoder = Halite::choose_encoder($encoding);
        if ($encoder) {
            return (string) $encoder($mac);
        }
        return $mac;
    }
    /**
     * Decrypt a message using the Halite encryption protocol
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decrypt(string $ciphertext, Encryption_Key $secret_key, bool|string $encoding = Halite::ENCODE_BASE64URLSAFE): Hidden_String
    {
        return self::decrypt_with_ad($ciphertext, $secret_key, '', $encoding);
    }
    /**
     * Decrypt a message using the Halite encryption protocol
     *
     * Verifies the MAC before decryption
     * - Halite 5+ verifies the BLAKE2b-MAC before decrypting with XChaCha20
     * - Halite 4 and below verifies the BLAKE2b-MAC before decrypting with XSalsa20
     *
     * You don't need to worry about chosen-ciphertext attacks.
     * You don't need to worry about Invisible Salamanders.
     * You don't need to worry about timing attacks on MAC validation.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decrypt_with_ad(string $ciphertext, Encryption_Key $secret_key, string $additional_data = '', bool|string $encoding = Halite::ENCODE_BASE64URLSAFE): Hidden_String
    {
        $decoder = Halite::choose_encoder($encoding, true);
        if (is_callable($decoder)) {
            // We were given encoded data:
            // @codeCoverageIgnoreStart
            try {
                /** @var string $ciphertext */
                $ciphertext = $decoder($ciphertext);
            } catch (RangeException) {
                throw new Invalid_Message('Invalid character encoding');
            }
            // @codeCoverageIgnoreEnd
        }
        /**
         * @var string $version
         * @var Config $config
         * @var string $salt
         * @var string $nonce
         * @var string $encrypted
         * @var string $auth
         */
        [$version, $config, $salt, $nonce, $encrypted, $auth] = self::unpack_message_for_decryption($ciphertext);
        /* Split our key into two keys: One for encryption, the other for
                   authentication. By using separate keys, we can reasonably dismiss
                   likely cross-protocol attacks.
        
                   This uses salted HKDF to split the keys, which is why we need the
                   salt in the first place. */
        /** @var array<int, string> $split */
        $split = Util::split_keys($secret_key, $salt, $config);
        $enc_key = $split[0];
        $auth_key = $split[1];
        // Check the MAC first
        if ($config->USE_PAE) {
            $verified = self::verify_mac($auth, Util::PAE($version, $salt, $nonce, $additional_data, $encrypted), $auth_key, $config);
        } else {
            $verified = self::verify_mac(
                // @codeCoverageIgnoreStart
                $auth,
                $version . $salt . $nonce . $additional_data . $encrypted,
                // @codeCoverageIgnoreEnd
                $auth_key,
                $config
            );
        }
        if (!$verified) {
            throw new Invalid_Message('Invalid message authentication code');
        }
        Util::memzero($salt);
        Util::memzero($auth_key);
        // crypto_stream_xor() can be used to encrypt and decrypt
        if ($config->ENC_ALGO === 'XChaCha20') {
            $plaintext = sodium_crypto_stream_xchacha20_xor($encrypted, $nonce, $enc_key);
        } else {
            $plaintext = sodium_crypto_stream_xor($encrypted, $nonce, $enc_key);
        }
        Util::memzero($encrypted);
        Util::memzero($nonce);
        Util::memzero($enc_key);
        return new Hidden_String($plaintext);
    }
    /**
     * Encrypt a message using the Halite encryption protocol
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encrypt(Hidden_String $plaintext, Encryption_Key $secret_key, bool|string $encoding = Halite::ENCODE_BASE64URLSAFE): string
    {
        return self::encrypt_with_ad($plaintext, $secret_key, '', $encoding);
    }
    /**
     * Encrypt a message using the Halite encryption protocol
     *
     * Encrypt then MAC.
     * - Halite 5+ uses XChaCha20 then BLAKE2b-MAC
     * - Halite 4 and below use XSalsa20 then BLAKE2b-MAC
     *
     * You don't need to worry about chosen-ciphertext attacks.
     * You don't need to worry about Invisible Salamanders.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encrypt_with_ad(Hidden_String $plaintext, Encryption_Key $secret_key, string $additional_data = '', bool|string $encoding = Halite::ENCODE_BASE64URLSAFE): string
    {
        $config = Symmetric_Config::get_config(Halite::HALITE_VERSION, 'encrypt');
        // Generate a nonce and HKDF salt:
        // @codeCoverageIgnoreStart
        try {
            $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $salt = random_bytes((int) $config->HKDF_SALT_LEN);
        } catch (Throwable $ex) {
            throw new Cannot_Perform_Operation($ex->get_message());
        }
        // @codeCoverageIgnoreEnd
        /* Split our key into two keys: One for encryption, the other for
                   authentication. By using separate keys, we can reasonably dismiss
                   likely cross-protocol attacks.
        
                   This uses salted HKDF to split the keys, which is why we need the
                   salt in the first place. */
        [$enc_key, $auth_key] = Util::split_keys($secret_key, $salt, $config);
        // Encrypt our message with the encryption key:
        if ($config->ENC_ALGO === 'XChaCha20') {
            $encrypted = sodium_crypto_stream_xchacha20_xor($plaintext->get_string(), $nonce, $enc_key);
        } else {
            $encrypted = sodium_crypto_stream_xor($plaintext->get_string(), $nonce, $enc_key);
        }
        Util::memzero($enc_key);
        // Calculate an authentication tag:
        if ($config->USE_PAE) {
            $auth = self::calculate_mac(Util::PAE(Halite::HALITE_VERSION, $salt, $nonce, $additional_data, $encrypted), $auth_key, $config);
        } else {
            $auth = self::calculate_mac(Halite::HALITE_VERSION . $salt . $nonce . $additional_data . $encrypted, $auth_key, $config);
        }
        Util::memzero($auth_key);
        $message = Halite::HALITE_VERSION . $salt . $nonce . $encrypted . $auth;
        // Wipe every superfluous piece of data from memory
        Util::memzero($nonce);
        Util::memzero($salt);
        Util::memzero($encrypted);
        Util::memzero($auth);
        $encoder = Halite::choose_encoder($encoding);
        if ($encoder) {
            return (string) $encoder($message);
        }
        return $message;
    }
    /**
     * Unpack a message string into an array (assigned to variables via list()).
     *
     * Should return exactly 6 elements.
     *
     *
     * @return array<int, mixed>
     *
     * @throws InvalidMessage
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function unpack_message_for_decryption(string $ciphertext): array
    {
        $length = Binary::safe_strlen($ciphertext);
        // Fail fast on invalid messages
        if ($length < Halite::VERSION_TAG_LEN) {
            throw new Invalid_Message('Message is too short');
        }
        // The first 4 bytes are reserved for the version size
        $version = Binary::safe_substr($ciphertext, 0, Halite::VERSION_TAG_LEN);
        $config = Symmetric_Config::get_config($version, 'encrypt');
        if ($length < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new Invalid_Message('Message is too short');
        }
        // The salt is used for key splitting (via HKDF)
        $salt = Binary::safe_substr($ciphertext, Halite::VERSION_TAG_LEN, (int) $config->HKDF_SALT_LEN);
        // This is the nonce (we authenticated it):
        $nonce = Binary::safe_substr(
            $ciphertext,
            // 36:
            Halite::VERSION_TAG_LEN + (int) $config->HKDF_SALT_LEN,
            // 24:
            SODIUM_CRYPTO_STREAM_NONCEBYTES
        );
        // This is the crypto_stream_xor()ed ciphertext
        $encrypted = Binary::safe_substr(
            $ciphertext,
            // 60:
            Halite::VERSION_TAG_LEN + (int) $config->HKDF_SALT_LEN + SODIUM_CRYPTO_STREAM_NONCEBYTES,
            // $length - 124
            $length - (Halite::VERSION_TAG_LEN + (int) $config->HKDF_SALT_LEN + SODIUM_CRYPTO_STREAM_NONCEBYTES + (int) $config->MAC_SIZE)
        );
        // $auth is the last 32 bytes
        $auth = Binary::safe_substr($ciphertext, $length - (int) $config->MAC_SIZE);
        // We don't need this anymore.
        Util::memzero($ciphertext);
        // Now we return the pieces in a specific order:
        return [$version, $config, $salt, $nonce, $encrypted, $auth];
    }
    /**
     * Verify the authenticity of a message, given a shared MAC key
     *
     *
     *
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify(string $message, Authentication_Key $secret_key, string $mac, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE, ?Symmetric_Config $config = null): bool
    {
        $decoder = Halite::choose_encoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            /** @var string $mac */
            $mac = $decoder($mac);
        }
        if (is_null($config)) {
            // Default to the current version
            $config = Symmetric_Config::get_config(Halite::HALITE_VERSION, 'auth');
        }
        try {
            return self::verify_mac($mac, $message, $secret_key->get_raw_key_material(), $config);
            // @codeCoverageIgnoreStart
        } catch (Invalid_Message) {
            return false;
            // @codeCoverageIgnoreEnd
        }
    }
    /**
     * Calculate a MAC. This is used internally.
     *
     *
     *
     * @throws InvalidMessage
     * @throws SodiumException
     */
    protected static function calculate_mac(string $message, string $auth_key, Symmetric_Config $config): string
    {
        if ($config->MAC_ALGO === 'BLAKE2b') {
            return sodium_crypto_generichash($message, $auth_key, (int) $config->MAC_SIZE);
        }
        // @codeCoverageIgnoreStart
        throw new Invalid_Message('Invalid Halite version');
        // @codeCoverageIgnoreEnd
    }
    /**
     * Verify a Message Authentication Code (MAC) of a message, with a shared
     * key.
     *
     * @param string $mac              Message Authentication Code
     * @param string $message          The message to verify
     * @param string $authKey          Authentication key (symmetric)
     * @param SymmetricConfig $config  Configuration object
     *
     *
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws SodiumException
     */
    protected static function verify_mac(string $mac, string $message, string $auth_key, Symmetric_Config $config): bool
    {
        if (Binary::safe_strlen($mac) !== $config->MAC_SIZE) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Signature('Argument 1: Message Authentication Code is not the correct length; is it encoded?');
            // @codeCoverageIgnoreEnd
        }
        if ($config->MAC_ALGO === 'BLAKE2b') {
            $calc = sodium_crypto_generichash($message, $auth_key, (int) $config->MAC_SIZE);
            $res = hash_equals($mac, $calc);
            Util::memzero($calc);
            return $res;
        }
        // @codeCoverageIgnoreStart
        throw new Invalid_Message('Invalid Halite version');
        // @codeCoverageIgnoreEnd
    }
}