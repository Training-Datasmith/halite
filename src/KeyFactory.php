<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use function file_get_contents;
use function file_put_contents;
use function hash_equals;
use function is_int;
use function is_readable;
use Paragon_Ie\Constant_Time\{Binary, Hex};
use Paragon_Ie\Halite\{Asymmetric\Encryption_Public_Key, Asymmetric\Encryption_Secret_Key, Asymmetric\Signature_Public_Key, Asymmetric\Signature_Secret_Key, Symmetric\Authentication_Key, Symmetric\Encryption_Key};
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Key, Invalid_Salt, Invalid_Type};
use Paragon_Ie\Hidden_String\Hidden_String;
use function random_bytes;
use const SODIUM_CRYPTO_AUTH_KEYBYTES;
use function sodium_crypto_box_keypair;
use function sodium_crypto_box_publickey;
use function sodium_crypto_box_secretkey;
use function sodium_crypto_box_seed_keypair;
use const SODIUM_CRYPTO_BOX_SEEDBYTES;
use function sodium_crypto_generichash;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use function sodium_crypto_pwhash;
use const SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;
use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE;
use const SODIUM_CRYPTO_PWHASH_SALTBYTES;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;
use function sodium_crypto_sign_seed_keypair;
use const SODIUM_CRYPTO_SIGN_SEEDBYTES;
use const SODIUM_CRYPTO_STREAM_KEYBYTES;
use Sodium_Exception;
use Throwable;
use TypeError;
/**
 * Class KeyFactory
 *
 * Class for generating specific key types
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
final class Key_Factory
{
    // For key derivation security levels:
    public const INTERACTIVE = 'interactive';
    public const MODERATE = 'moderate';
    public const SENSITIVE = 'sensitive';
    /**
     * Generate an authentication key (symmetric-key cryptography)
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws \TypeError
     */
    public static function generate_authentication_key(): Authentication_Key
    {
        // @codeCoverageIgnoreStart
        try {
            $secret_key = random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES);
        } catch (Throwable $ex) {
            throw new Cannot_Perform_Operation($ex->get_message());
        }
        // @codeCoverageIgnoreEnd
        return new Authentication_Key(new Hidden_String($secret_key));
    }
    /**
     * Generate an encryption key (symmetric-key cryptography)
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws TypeError
     */
    public static function generate_encryption_key(): Encryption_Key
    {
        // @codeCoverageIgnoreStart
        try {
            $secret_key = random_bytes(SODIUM_CRYPTO_STREAM_KEYBYTES);
        } catch (Throwable $ex) {
            throw new Cannot_Perform_Operation($ex->get_message());
        }
        // @codeCoverageIgnoreEnd
        return new Encryption_Key(new Hidden_String($secret_key));
    }
    /**
     * Generate a key pair for public key encryption
     *
     *
     * @throws InvalidKey
     * @throws TypeError
     * @throws SodiumException
     */
    public static function generate_encryption_key_pair(): Encryption_Key_Pair
    {
        // Encryption keypair
        $kp = sodium_crypto_box_keypair();
        $secret_key = sodium_crypto_box_secretkey($kp);
        $public_key = sodium_crypto_box_publickey($kp);
        // Let's wipe our $kp variable
        Util::memzero($kp);
        return new Encryption_Key_Pair(new Encryption_Secret_Key(new Hidden_String($secret_key), new Hidden_String($public_key)));
    }
    /**
     * Generate a key pair for public key digital signatures
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function generate_signature_key_pair(): Signature_Key_Pair
    {
        // Encryption keypair
        $kp = sodium_crypto_sign_keypair();
        $secret_key = sodium_crypto_sign_secretkey($kp);
        $public_key = sodium_crypto_sign_publickey($kp);
        // Let's wipe our $kp variable
        Util::memzero($kp);
        return new Signature_Key_Pair(new Signature_Secret_Key(new Hidden_String($secret_key), new Hidden_String($public_key)));
    }
    /**
     * Derive an authentication key (symmetric) from a password and salt
     *
     * @param string $level Security level for KDF
     * @param int $alg      Which Argon2 variant to use?
     *                      (You can safely use the default)
     *
     *
     * @throws InvalidKey
     * @throws InvalidSalt
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function derive_authentication_key(Hidden_String $password, string $salt, string $level = self::INTERACTIVE, int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13): Authentication_Key
    {
        $kdf_limits = self::get_security_levels($level, $alg);
        // VERSION 2+ (argon2)
        if (Binary::safe_strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Salt('Expected ' . SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Binary::safe_strlen($salt));
            // @codeCoverageIgnoreEnd
        }
        $secret_key = sodium_crypto_pwhash(SODIUM_CRYPTO_AUTH_KEYBYTES, $password->get_string(), $salt, $kdf_limits[0], $kdf_limits[1], $alg);
        return new Authentication_Key(new Hidden_String($secret_key));
    }
    /**
     * Derive an encryption key (symmetric-key cryptography) from a password
     * and salt
     *
     * @param string $level Security level for KDF
     * @param int $alg      Which Argon2 variant to use?
     *                      (You can safely use the default)
     *
     *
     * @throws InvalidKey
     * @throws InvalidSalt
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function derive_encryption_key(Hidden_String $password, string $salt, string $level = self::INTERACTIVE, int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13): Encryption_Key
    {
        $kdf_limits = self::get_security_levels($level, $alg);
        // VERSION 2+ (argon2)
        if (Binary::safe_strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Salt('Expected ' . SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Binary::safe_strlen($salt));
            // @codeCoverageIgnoreEnd
        }
        $secret_key = sodium_crypto_pwhash(SODIUM_CRYPTO_STREAM_KEYBYTES, $password->get_string(), $salt, $kdf_limits[0], $kdf_limits[1], $alg);
        return new Encryption_Key(new Hidden_String($secret_key));
    }
    /**
     * Derive a key pair for public key encryption from a password and salt
     *
     * @param string $level Security level for KDF
     * @param int $alg      Which Argon2 variant to use?
     *                      (You can safely use the default)
     *
     *
     * @throws InvalidKey
     * @throws InvalidSalt
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function derive_encryption_key_pair(Hidden_String $password, string $salt, string $level = self::INTERACTIVE, int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13): Encryption_Key_Pair
    {
        $kdf_limits = self::get_security_levels($level, $alg);
        // VERSION 2+ (argon2)
        if (Binary::safe_strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Salt('Expected ' . SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Binary::safe_strlen($salt));
            // @codeCoverageIgnoreEnd
        }
        // Diffie Hellman key exchange key pair
        $seed = sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_SEEDBYTES, $password->get_string(), $salt, $kdf_limits[0], $kdf_limits[1], $alg);
        $key_pair = sodium_crypto_box_seed_keypair($seed);
        $secret_key = sodium_crypto_box_secretkey($key_pair);
        $public_key = sodium_crypto_box_publickey($key_pair);
        // Let's wipe our $kp variable
        Util::memzero($key_pair);
        return new Encryption_Key_Pair(new Encryption_Secret_Key(new Hidden_String($secret_key), new Hidden_String($public_key)));
    }
    /**
     * Derive a key pair for public key signatures from a password and salt
     *
     * @param string $level Security level for KDF
     * @param int $alg      Which Argon2 variant to use?
     *                      (You can safely use the default)
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidSalt
     * @throws InvalidType
     * @throws SodiumException
     */
    public static function derive_signature_key_pair(Hidden_String $password, string $salt, string $level = self::INTERACTIVE, int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13): Signature_Key_Pair
    {
        $kdf_limits = self::get_security_levels($level, $alg);
        // VERSION 2+ (argon2)
        if (Binary::safe_strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Salt('Expected ' . SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Binary::safe_strlen($salt));
            // @codeCoverageIgnoreEnd
        }
        // Digital signature keypair
        $seed = sodium_crypto_pwhash(SODIUM_CRYPTO_SIGN_SEEDBYTES, $password->get_string(), $salt, $kdf_limits[0], $kdf_limits[1], $alg);
        $key_pair = sodium_crypto_sign_seed_keypair($seed);
        $secret_key = sodium_crypto_sign_secretkey($key_pair);
        $public_key = sodium_crypto_sign_publickey($key_pair);
        // Let's wipe our $kp variable
        Util::memzero($key_pair);
        return new Signature_Key_Pair(new Signature_Secret_Key(new Hidden_String($secret_key), new Hidden_String($public_key)));
    }
    /**
     * Returns a 2D array [OPSLIMIT, MEMLIMIT] for the appropriate security level.
     *
     *
     * @return int[]
     * @throws InvalidType
     * @codeCoverageIgnore
     */
    public static function get_security_levels(string $level = self::INTERACTIVE, int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13): array
    {
        switch ($level) {
            case self::INTERACTIVE:
                if ($alg === SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13) {
                    // legacy opslimit and memlimit
                    return [4, 33554432];
                }
                return [SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE];
            case self::MODERATE:
                if ($alg === SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13) {
                    // legacy opslimit and memlimit
                    return [6, 134217728];
                }
                return [SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE];
            case self::SENSITIVE:
                if ($alg === SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13) {
                    // legacy opslimit and memlimit
                    return [8, 536870912];
                }
                return [SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE];
            default:
                throw new Invalid_Type('Invalid security level for Argon2i');
        }
    }
    /**
     * Load a symmetric authentication key from a string
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_authentication_key(Hidden_String $key_data): Authentication_Key
    {
        return new Authentication_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string()))));
    }
    /**
     * Load a symmetric encryption key from a string
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_encryption_key(Hidden_String $key_data): Encryption_Key
    {
        return new Encryption_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string()))));
    }
    /**
     * Load, specifically, an encryption public key from a string
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_encryption_public_key(Hidden_String $key_data): Encryption_Public_Key
    {
        return new Encryption_Public_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string()))));
    }
    /**
     * Load, specifically, an encryption secret key from a string
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_encryption_secret_key(Hidden_String $key_data): Encryption_Secret_Key
    {
        return new Encryption_Secret_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string()))));
    }
    /**
     * Load, specifically, a signature public key from a string
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_signature_public_key(Hidden_String $key_data): Signature_Public_Key
    {
        return new Signature_Public_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string()))));
    }
    /**
     * Load, specifically, a signature secret key from a string
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_signature_secret_key(Hidden_String $key_data): Signature_Secret_Key
    {
        return new Signature_Secret_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string()))));
    }
    /**
     * Load an asymmetric encryption key pair from a string
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_encryption_key_pair(Hidden_String $key_data): Encryption_Key_Pair
    {
        return new Encryption_Key_Pair(new Encryption_Secret_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string())))));
    }
    /**
     * Load an asymmetric signature key pair from a string
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function import_signature_key_pair(Hidden_String $key_data): Signature_Key_Pair
    {
        return new Signature_Key_Pair(new Signature_Secret_Key(new Hidden_String(self::get_key_data_from_string(Hex::decode($key_data->get_string())))));
    }
    /**
     * Load a symmetric authentication key from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_authentication_key(string $file_path): Authentication_Key
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Authentication_Key(self::load_key_file($file_path));
    }
    /**
     * Load a symmetric encryption key from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_encryption_key(string $file_path): Encryption_Key
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Encryption_Key(self::load_key_file($file_path));
    }
    /**
     * Load, specifically, an encryption public key from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_encryption_public_key(string $file_path): Encryption_Public_Key
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Encryption_Public_Key(self::load_key_file($file_path));
    }
    /**
     * Load, specifically, an encryption public key from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_encryption_secret_key(string $file_path): Encryption_Secret_Key
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Encryption_Secret_Key(self::load_key_file($file_path));
    }
    /**
     * Load, specifically, a signature public key from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_signature_public_key(string $file_path): Signature_Public_Key
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Signature_Public_Key(self::load_key_file($file_path));
    }
    /**
     * Load, specifically, a signature secret key from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_signature_secret_key(string $file_path): Signature_Secret_Key
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Signature_Secret_Key(self::load_key_file($file_path));
    }
    /**
     * Load an asymmetric encryption key pair from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_encryption_key_pair(string $file_path): Encryption_Key_Pair
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Encryption_Key_Pair(new Encryption_Secret_Key(self::load_key_file($file_path)));
    }
    /**
     * Load an asymmetric signature key pair from a file
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function load_signature_key_pair(string $file_path): Signature_Key_Pair
    {
        if (!is_readable($file_path)) {
            throw new Cannot_Perform_Operation('Cannot read keyfile: ' . $file_path);
        }
        return new Signature_Key_Pair(new Signature_Secret_Key(self::load_key_file($file_path)));
    }
    /**
     * Export a cryptography key to a string (with a checksum)
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function export(Key|Key_Pair $key): Hidden_String
    {
        if ($key instanceof Key_Pair) {
            return self::export($key->get_secret_key());
        }
        return new Hidden_String(Hex::encode(Halite::HALITE_VERSION_KEYS . $key->get_raw_key_material() . sodium_crypto_generichash(Halite::HALITE_VERSION_KEYS . $key->get_raw_key_material(), '', SODIUM_CRYPTO_GENERICHASH_BYTES_MAX)));
    }
    /**
     * Save a key to a file
     *
     *
     *
     * @throws SodiumException
     * @throws TypeError
     */
    public static function save(Key|Key_Pair $key, string $filename = ''): bool
    {
        if ($key instanceof Key_Pair) {
            return self::save_key_file($filename, $key->get_secret_key()->get_raw_key_material());
        }
        return self::save_key_file($filename, $key->get_raw_key_material());
    }
    /**
     * Read a key from a file, verify its checksum
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    protected static function load_key_file(string $file_path): Hidden_String
    {
        $file_data = file_get_contents($file_path);
        if ($file_data === false) {
            // @codeCoverageIgnoreStart
            throw new Cannot_Perform_Operation('Cannot load key from file: ' . $file_path);
            // @codeCoverageIgnoreEnd
        }
        $data = Hex::decode($file_data);
        Util::memzero($file_data);
        return new Hidden_String(self::get_key_data_from_string($data));
    }
    /**
     * Take a stored key string, get the derived key (after verifying the
     * checksum)
     *
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function get_key_data_from_string(string $data): string
    {
        $version_tag = Binary::safe_substr($data, 0, Halite::VERSION_TAG_LEN);
        $key_data = Binary::safe_substr($data, Halite::VERSION_TAG_LEN, -SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        $checksum = Binary::safe_substr($data, -SODIUM_CRYPTO_GENERICHASH_BYTES_MAX, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        $calc = sodium_crypto_generichash($version_tag . $key_data, '', SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        if (!hash_equals($calc, $checksum)) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Key('Checksum validation fail');
            // @codeCoverageIgnoreEnd
        }
        Util::memzero($data);
        Util::memzero($version_tag);
        Util::memzero($calc);
        Util::memzero($checksum);
        return $key_data;
    }
    /**
     * Save a key to a file
     *
     *
     * @throws SodiumException
     * @throws TypeError
     */
    protected static function save_key_file(string $file_path, string $key_data): bool
    {
        $saved = file_put_contents($file_path, Hex::encode(Halite::HALITE_VERSION_KEYS . $key_data . sodium_crypto_generichash(Halite::HALITE_VERSION_KEYS . $key_data, '', SODIUM_CRYPTO_GENERICHASH_BYTES_MAX)));
        if (is_int($saved)) {
            // Restrict key file to owner read/write only (0600) to prevent world-readable key material
            chmod($file_path, 0600);
            return true;
        }
        return false;
    }
}