<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use function hash_equals;
use Paragon_Ie\Constant_Time\{Base64url_Safe, Binary, Hex};
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Digest_Length, Invalid_Message, Invalid_Signature, Invalid_Type};
use Paragon_Ie\Halite\Symmetric\{Config as SymmetricConfig, Crypto, Encryption_Key};
use Paragon_Ie\Hidden_String\Hidden_String;
use function sodium_crypto_pwhash_str;
use function sodium_crypto_pwhash_str_verify;
use const SODIUM_CRYPTO_PWHASH_STRPREFIX;
use Sodium_Exception;
use TypeError;
/**
 * Class Password
 *
 * Secure password storage and secure password verification
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
final class Password
{
    /**
     * Hash then encrypt a password
     *
     * @param HiddenString $password    The user's password
     * @param EncryptionKey $secretKey  The master key for all passwords
     * @param string $level             The security level for this password
     * @param string $additionalData    Additional authenticated data
     *
     * @return string                   An encrypted hash to store
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function hash(
        #[\Sensitive_Parameter]
        Hidden_String $password,
        #[\Sensitive_Parameter]
        Encryption_Key $secret_key,
        string $level = Key_Factory::INTERACTIVE,
        #[\Sensitive_Parameter]
        string $additional_data = ''
    ): string
    {
        $kdf_limits = Key_Factory::get_security_levels($level);
        // First, let's calculate the hash
        $hashed = sodium_crypto_pwhash_str($password->get_string(), $kdf_limits[0], $kdf_limits[1]);
        // Now let's encrypt the result
        return Crypto::encrypt_with_ad(new Hidden_String($hashed), $secret_key, $additional_data);
    }
    /**
     * Is this password hash stale?
     *
     * @param string $stored            Encrypted password hash
     * @param EncryptionKey $secretKey  The master key for all passwords
     * @param string $level             The security level for this password
     * @param string $additionalData    Additional authenticated data (if used to encrypt, mandatory)
     *
     * @return bool                     Do we need to regenerate the hash or
     *                                  ciphertext?
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function needs_rehash(
        #[\Sensitive_Parameter]
        string $stored,
        #[\Sensitive_Parameter]
        Encryption_Key $secret_key,
        string $level = Key_Factory::INTERACTIVE,
        #[\Sensitive_Parameter]
        string $additional_data = ''
    ): bool
    {
        $config = self::get_config($stored);
        if (Binary::safe_strlen($stored) < (int) $config->SHORTEST_CIPHERTEXT_LENGTH * 4 / 3) {
            throw new Invalid_Message('Encrypted password hash is too short.');
        }
        $encoding = $config->ENCODING;
        // First let's decrypt the hash
        $hash_str = Crypto::decrypt_with_ad($stored, $secret_key, $additional_data, $encoding)->get_string();
        // Upon successful decryption, verify that we're using Argon2id
        if (!hash_equals(Binary::safe_substr($hash_str, 0, 10), SODIUM_CRYPTO_PWHASH_STRPREFIX)) {
            return true;
        }
        // Parse the cost parameters:
        return match ($level) {
            Key_Factory::INTERACTIVE => !hash_equals('$argon2id$v=19$m=65536,t=2,p=1$', Binary::safe_substr($hash_str, 0, 31)),
            Key_Factory::MODERATE => !hash_equals('$argon2id$v=19$m=262144,t=3,p=1$', Binary::safe_substr($hash_str, 0, 32)),
            Key_Factory::SENSITIVE => !hash_equals('$argon2id$v=19$m=1048576,t=4,p=1$', Binary::safe_substr($hash_str, 0, 33)),
            default => true,
        };
    }
    /**
     * Get the configuration for this version of halite
     *
     * @param string $stored   A stored password hash
     * @throws InvalidMessage
     * @throws \TypeError
     */
    protected static function get_config(string $stored): Symmetric_Config
    {
        $length = Binary::safe_strlen($stored);
        // This doesn't even have a header.
        if ($length < 8) {
            throw new Invalid_Message('Encrypted password hash is way too short.');
        }
        $prefix = Binary::safe_substr($stored, 0, 5);
        if (hash_equals($prefix, Halite::VERSION_PREFIX) || hash_equals($prefix, Halite::VERSION_OLD_PREFIX)) {
            $decoded = Base64url_Safe::decode($stored);
            return Symmetric_Config::get_config($decoded, 'encrypt');
        }
        // @codeCoverageIgnoreStart
        $v = Hex::decode(Binary::safe_substr($stored, 0, 8));
        return Symmetric_Config::get_config($v, 'encrypt');
        // @codeCoverageIgnoreEnd
    }
    /**
     * Decrypt then verify a password
     *
     * @param HiddenString $password    The user's password
     * @param string $stored            The encrypted password hash
     * @param EncryptionKey $secretKey  The master key for all passwords
     * @param string $additionalData    Additional authenticated data (needed to decrypt)
     *
     * @return bool                     Is this password valid?
     *
     * @throws Alerts\InvalidSignature
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify(
        #[\Sensitive_Parameter]
        Hidden_String $password,
        #[\Sensitive_Parameter]
        string $stored,
        #[\Sensitive_Parameter]
        Encryption_Key $secret_key,
        #[\Sensitive_Parameter]
        string $additional_data = ''
    ): bool
    {
        $config = self::get_config($stored);
        // Base64-urlsafe encoded, so 4/3 the size of raw binary
        if (Binary::safe_strlen($stored) < (int) $config->SHORTEST_CIPHERTEXT_LENGTH * 4 / 3) {
            throw new Invalid_Message('Encrypted password hash is too short.');
        }
        $encoding = $config->ENCODING;
        // First let's decrypt the hash
        $hash_str = Crypto::decrypt_with_ad($stored, $secret_key, $additional_data, $encoding);
        // Upon successful decryption, verify the password is correct
        return sodium_crypto_pwhash_str_verify($hash_str->get_string(), $password->get_string());
    }
}