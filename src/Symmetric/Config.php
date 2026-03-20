<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Symmetric;

use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\{Config as BaseConfig, Halite, Util};
use Paragon_Ie\Halite\Alerts\Invalid_Message;
use const SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use const SODIUM_CRYPTO_STREAM_NONCEBYTES;
/**
 * Class Config
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
final class Config extends Base_Config
{
    /**
     * Get the configuration
     *
     *
     *
     * @throws InvalidMessage
     */
    public static function get_config(string $header, string $mode = 'encrypt'): self
    {
        if (Binary::safe_strlen($header) < Halite::VERSION_TAG_LEN) {
            throw new Invalid_Message('Invalid version tag');
        }
        if (Util::chr_to_int($header[0]) !== 49 || Util::chr_to_int($header[1]) !== 66) {
            throw new Invalid_Message('Invalid version tag');
        }
        $major = Util::chr_to_int($header[2]);
        $minor = Util::chr_to_int($header[3]);
        if ($mode === 'encrypt') {
            return new Config(self::get_config_encrypt($major, $minor));
        }
        if ($mode === 'auth') {
            return new Config(self::get_config_auth($major, $minor));
        }
        throw new Invalid_Message('Invalid configuration mode: ' . $mode);
    }
    /**
     * Get the configuration for encrypt operations
     *
     *
     *
     * @throws InvalidMessage
     */
    public static function get_config_encrypt(int $major, int $minor): array
    {
        if ($major === 5) {
            switch ($minor) {
                case 0:
                    return ['ENCODING' => Halite::ENCODE_BASE64URLSAFE, 'SHORTEST_CIPHERTEXT_LENGTH' => 124, 'NONCE_BYTES' => SODIUM_CRYPTO_STREAM_NONCEBYTES, 'HKDF_SALT_LEN' => 32, 'ENC_ALGO' => 'XChaCha20', 'USE_PAE' => true, 'MAC_ALGO' => 'BLAKE2b', 'MAC_SIZE' => SODIUM_CRYPTO_GENERICHASH_BYTES_MAX, 'HKDF_USE_INFO' => true, 'HKDF_SBOX' => 'Halite|EncryptionKey', 'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'];
            }
        }
        if ($major === 4 || $major === 3) {
            switch ($minor) {
                case 0:
                    return ['ENCODING' => Halite::ENCODE_BASE64URLSAFE, 'SHORTEST_CIPHERTEXT_LENGTH' => 124, 'NONCE_BYTES' => SODIUM_CRYPTO_STREAM_NONCEBYTES, 'HKDF_SALT_LEN' => 32, 'ENC_ALGO' => 'XSalsa20', 'USE_PAE' => false, 'MAC_ALGO' => 'BLAKE2b', 'MAC_SIZE' => SODIUM_CRYPTO_GENERICHASH_BYTES_MAX, 'HKDF_USE_INFO' => false, 'HKDF_SBOX' => 'Halite|EncryptionKey', 'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'];
            }
        }
        throw new Invalid_Message('Invalid version tag');
    }
    /**
     * Get the configuration for seal operations
     *
     *
     *
     * @throws InvalidMessage
     */
    public static function get_config_auth(int $major, int $minor): array
    {
        if ($major === 4 || $major === 5) {
            switch ($minor) {
                case 0:
                    return ['USE_PAE' => $major >= 5, 'HKDF_SALT_LEN' => 32, 'MAC_ALGO' => 'BLAKE2b', 'MAC_SIZE' => SODIUM_CRYPTO_GENERICHASH_BYTES_MAX, 'PUBLICKEY_BYTES' => SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'HKDF_USE_INFO' => $major > 4, 'HKDF_SBOX' => 'Halite|EncryptionKey', 'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'];
            }
        }
        throw new Invalid_Message('Invalid version tag');
    }
}