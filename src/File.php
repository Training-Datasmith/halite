<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use function array_shift;
use Error;
use Exception;
use function hash_equals;
use function is_string;
use function pack;
use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\{Asymmetric\Crypto as AsymmetricCrypto, Asymmetric\Encryption_Public_Key, Asymmetric\Encryption_Secret_Key, Asymmetric\Signature_Public_Key, Asymmetric\Signature_Secret_Key, Contract\Stream_Interface, Stream\Mutable_File, Stream\Read_Only_File, Symmetric\Authentication_Key, Symmetric\Config as SymmetricConfig, Symmetric\Encryption_Key};
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, File_Access_Denied, File_Error, File_Modified, Invalid_Digest_Length, Invalid_Key, Invalid_Message, Invalid_Signature, Invalid_Type};
use Paragon_Ie\Hidden_String\Hidden_String;
use function random_bytes;
use const SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
use function sodium_crypto_generichash;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use function sodium_crypto_generichash_final;
use function sodium_crypto_generichash_init;
use function sodium_crypto_generichash_update;
use function sodium_crypto_scalarmult;
use const SODIUM_CRYPTO_STREAM_NONCEBYTES;
use function sodium_increment;
use Sodium_Exception;
use Throwable;
use TypeError;
/**
 * Class File
 *
 * Cryptography operations for the filesystem.
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
final class File
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
     * Calculate the BLAKE2b-512 checksum of a file. This method doesn't load
     * the entire file into memory. You may optionally supply a key to use in
     * the BLAKE2b hash.
     *
     * @param ?Key $key (optional; expects SignaturePublicKey or
     *                  AuthenticationKey)
     * @param bool|string $encoding Which encoding scheme to use for the checksum?
     * @return string         The checksum
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function checksum(string|Readonly_File $file_path, ?Key $key = null, bool|string $encoding = Halite::ENCODE_BASE64URLSAFE): string
    {
        if ($file_path instanceof Read_Only_File) {
            $pos = $file_path->get_pos();
            $file_path->reset(0);
            $checksum = self::checksum_data($file_path, $key, $encoding);
            $file_path->reset($pos);
            return $checksum;
        }
        $read_only = new Read_Only_File($file_path);
        try {
            return self::checksum_data($read_only, $key, $encoding);
        } finally {
            $read_only->close();
        }
    }
    /**
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     */
    public static function asymmetric_encrypt(string|Read_Only_File $input, string|Mutable_File $output, Encryption_Public_Key $recipient_pk, Encryption_Secret_Key $sender_sk, ?string $aad = null): int
    {
        try {
            $key = new Encryption_Key(new Hidden_String(sodium_crypto_generichash(sodium_crypto_scalarmult($sender_sk->get_raw_key_material(), $recipient_pk->get_raw_key_material()) . $sender_sk->derive_public_key()->get_raw_key_material() . $recipient_pk->get_raw_key_material())));
            if ($input instanceof Read_Only_File) {
                $read_only = $input;
            } else {
                $read_only = new Read_Only_File($input);
            }
            if ($output instanceof Mutable_File) {
                $mutable = $output;
            } else {
                $mutable = new Mutable_File($output);
            }
            return self::encrypt_data($read_only, $mutable, $key, $aad);
        } finally {
            if (isset($read_only)) {
                $read_only->close();
            }
            if (isset($mutable)) {
                $mutable->close();
            }
        }
    }
    /**
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     */
    public static function asymmetric_decrypt(string|Read_Only_File $input, string|Mutable_File $output, Encryption_Secret_Key $recipient_sk, Encryption_Public_Key $sender_pk, ?string $aad = null): bool
    {
        try {
            $key = new Encryption_Key(new Hidden_String(sodium_crypto_generichash(sodium_crypto_scalarmult($recipient_sk->get_raw_key_material(), $sender_pk->get_raw_key_material()) . $sender_pk->get_raw_key_material() . $recipient_sk->derive_public_key()->get_raw_key_material())));
            if ($input instanceof Read_Only_File) {
                $read_only = $input;
            } else {
                $read_only = new Read_Only_File($input);
            }
            if ($output instanceof Mutable_File) {
                $mutable = $output;
            } else {
                $mutable = new Mutable_File($output);
            }
            return self::decrypt_data($read_only, $mutable, $key, $aad);
        } finally {
            if (isset($read_only)) {
                $read_only->close();
            }
            if (isset($mutable)) {
                $mutable->close();
            }
        }
    }
    /**
     * Encrypt a file using symmetric authenticated encryption.
     *
     * @param string|ReadOnlyFile $input Input file
     * @param string|MutableFile $output Output file
     * @param EncryptionKey $key         Symmetric encryption key
     * @param string|null $aad           Additional authenticated data
     * @return int                       Number of bytes written
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     */
    public static function encrypt(string|Read_Only_File $input, string|Mutable_File $output, Encryption_Key $key, ?string $aad = null): int
    {
        try {
            if ($input instanceof Read_Only_File) {
                $read_only = $input;
            } else {
                $read_only = new Read_Only_File($input);
            }
            if ($output instanceof Mutable_File) {
                $mutable = $output;
            } else {
                $mutable = new Mutable_File($output);
            }
            return self::encrypt_data($read_only, $mutable, $key, $aad);
        } finally {
            if (isset($read_only)) {
                $read_only->close();
            }
            if (isset($mutable)) {
                $mutable->close();
            }
        }
    }
    /**
     * Decrypt a file using symmetric-key authenticated encryption.
     *
     * @param string|ReadOnlyFile $input Input file
     * @param string|MutableFile $output Output file
     * @param EncryptionKey $key         Symmetric encryption key
     * @param string|null $aad           Additional authenticated data
     * @return bool                      TRUE if successful
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     */
    public static function decrypt(string|Read_Only_File $input, string|Mutable_File $output, Encryption_Key $key, ?string $aad = null): bool
    {
        try {
            if ($input instanceof Read_Only_File) {
                $read_only = $input;
            } else {
                $read_only = new Read_Only_File($input);
            }
            if ($output instanceof Mutable_File) {
                $mutable = $output;
            } else {
                $mutable = new Mutable_File($output);
            }
            return self::decrypt_data($read_only, $mutable, $key, $aad);
        } finally {
            if (isset($read_only)) {
                $read_only->close();
            }
            if (isset($mutable)) {
                $mutable->close();
            }
        }
    }
    /**
     * Encrypt a file using anonymous public-key encryption (with ciphertext
     * authentication).
     *
     * @param string|ReadOnlyFile $input     Input file
     * @param string|MutableFile $output     Output file
     * @param EncryptionPublicKey $publicKey Recipient's encryption public key
     * @param string|null $aad               Additional authenticated data
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public static function seal(string|Read_Only_File $input, string|Mutable_File $output, Encryption_Public_Key $public_key, ?string $aad = null): int
    {
        try {
            if ($input instanceof Read_Only_File) {
                $read_only = $input;
            } else {
                $read_only = new Read_Only_File($input);
            }
            if ($output instanceof Mutable_File) {
                $mutable = $output;
            } else {
                $mutable = new Mutable_File($output);
            }
            return self::seal_data($read_only, $mutable, $public_key, $aad);
        } finally {
            if (isset($read_only)) {
                $read_only->close();
            }
            if (isset($mutable)) {
                $mutable->close();
            }
        }
    }
    /**
     * Decrypt a file using anonymous public-key encryption. Ciphertext
     * integrity is still assured thanks to the Encrypt-then-MAC construction.
     *
     * @param string|ReadOnlyFile $input     Input file
     * @param string|MutableFile $output     Output file
     * @param EncryptionSecretKey $secretKey Recipient's encryption secret key
     * @param string|null $aad               Additional authenticated data
     * @return bool                          TRUE on success
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function unseal(string|Read_Only_File $input, string|Mutable_File $output, Encryption_Secret_Key $secret_key, ?string $aad = null): bool
    {
        try {
            if ($input instanceof Read_Only_File) {
                $read_only = $input;
            } else {
                $read_only = new Read_Only_File($input);
            }
            if ($output instanceof Mutable_File) {
                $mutable = $output;
            } else {
                $mutable = new Mutable_File($output);
            }
            return self::unseal_data($read_only, $mutable, $secret_key, $aad);
        } finally {
            if (isset($read_only)) {
                $read_only->close();
            }
            if (isset($mutable)) {
                $mutable->close();
            }
        }
    }
    /**
     * Calculate a digital signature (Ed25519) of a file
     *
     * Specifically:
     * 1. Calculate the BLAKE2b-512 checksum of the file, with the signer's
     *    Ed25519 public key used as a BLAKE2b key.
     * 2. Sign the checksum with Ed25519, using the corresponding public key.
     *
     * @param string|ReadOnlyFile $filename File name or ReadOnlyFile object
     * @param SignatureSecretKey $secretKey Secret key for digital signatures
     * @param string|bool $encoding         Which encoding scheme to use for the signature?
     * @return string                       Detached signature for the file
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws TypeError
     */
    public static function sign(string|Read_Only_File $filename, Signature_Secret_Key $secret_key, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE): string
    {
        if ($filename instanceof Read_Only_File) {
            $pos = $filename->get_pos();
            $filename->reset(0);
            $signature = self::sign_data($filename, $secret_key, $encoding);
            $filename->reset($pos);
            return $signature;
        }
        $read_only = new Read_Only_File($filename);
        try {
            return self::sign_data($read_only, $secret_key, $encoding);
        } finally {
            $read_only->close();
        }
    }
    /**
     * Verify a digital signature for a file.
     *
     * @param string|ReadOnlyFile $filename File name or ReadOnlyFile object
     * @param SignaturePublicKey $publicKey Other party's signature public key
     * @param string $signature             The signature we received
     * @param string|bool $encoding         Which encoding scheme to use for the signature?
     *
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify(string|Read_Only_File $filename, Signature_Public_Key $public_key, string $signature, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE): bool
    {
        if ($filename instanceof Read_Only_File) {
            $pos = $filename->get_pos();
            $filename->reset(0);
            $verified = self::verify_data($filename, $public_key, $signature, $encoding);
            $filename->reset($pos);
            return $verified;
        }
        $read_only = new Read_Only_File($filename);
        try {
            return self::verify_data($read_only, $public_key, $signature, $encoding);
        } finally {
            $read_only->close();
        }
    }
    /**
     * Calculate the BLAKE2b checksum of the contents of a file
     *
     * @param string|bool $encoding Which encoding scheme to use for the checksum?
     *
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws TypeError
     * @throws SodiumException
     */
    protected static function checksum_data(Stream_Interface $file_stream, ?Key $key = null, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE): string
    {
        $config = self::get_config(Halite::HALITE_VERSION_FILE, 'checksum');
        // 1. Initialize the hash context
        if ($key instanceof Authentication_Key) {
            // AuthenticationKey is for HMAC, but we can use it for keyed hashes too
            $state = sodium_crypto_generichash_init($key->get_raw_key_material(), (int) $config->HASH_LEN);
        } elseif ($config->CHECKSUM_PUBKEY && $key instanceof Signature_Public_Key) {
            // In version 2, we use the public key as a hash key
            $state = sodium_crypto_generichash_init($key->get_raw_key_material(), (int) $config->HASH_LEN);
            // @codeCoverageIgnoreStart
        } elseif (isset($key)) {
            // @codeCoverageIgnoreEnd
            throw new Invalid_Key('Argument 2: Expected an instance of AuthenticationKey or SignaturePublicKey');
        } else {
            $state = sodium_crypto_generichash_init('', (int) $config->HASH_LEN);
        }
        // 2. Calculate the hash
        $size = $file_stream->get_size();
        while ($file_stream->remaining_bytes() > 0) {
            // Don't go past the file size even if $config->BUFFER is not an even multiple of it:
            if ($file_stream->get_pos() + (int) $config->BUFFER > $size) {
                $amount_to_read = $size - $file_stream->get_pos();
            } else {
                // @codeCoverageIgnoreStart
                $amount_to_read = (int) $config->BUFFER;
                // @codeCoverageIgnoreEnd
            }
            $read = $file_stream->read_bytes($amount_to_read);
            sodium_crypto_generichash_update($state, $read);
        }
        // 3. Do we want a raw checksum?
        $encoder = Halite::choose_encoder($encoding);
        if ($encoder) {
            return (string) $encoder(sodium_crypto_generichash_final(
                // @codeCoverageIgnoreStart
                $state,
                // @codeCoverageIgnoreEnd
                (int) $config->HASH_LEN
            ));
        }
        return sodium_crypto_generichash_final(
            // @codeCoverageIgnoreStart
            $state,
            // @codeCoverageIgnoreEnd
            (int) $config->HASH_LEN
        );
    }
    /**
     * @param string|null $aad    Additional authenticated data
     *
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws TypeError
     * @throws SodiumException
     */
    protected static function encrypt_data(Read_Only_File $input, Mutable_File $output, Encryption_Key $key, ?string $aad = null): int
    {
        /** @var SymmetricConfig $config */
        $config = self::get_config(Halite::HALITE_VERSION_FILE, 'encrypt');
        // Generate a nonce and HKDF salt
        // @codeCoverageIgnoreStart
        try {
            $first_nonce = random_bytes((int) $config->NONCE_BYTES);
            $hkdf_salt = random_bytes((int) $config->HKDF_SALT_LEN);
        } catch (Throwable $ex) {
            throw new Cannot_Perform_Operation($ex->get_message());
        }
        // @codeCoverageIgnoreEnd
        // Let's split our key
        [$enc_key, $auth_key] = Util::split_keys($key, $hkdf_salt, $config);
        // Write the header
        $output->write_bytes(Halite::HALITE_VERSION_FILE, Halite::VERSION_TAG_LEN);
        $output->write_bytes($first_nonce, SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $output->write_bytes($hkdf_salt, (int) $config->HKDF_SALT_LEN);
        // VERSION 2+ uses BMAC
        $mac = sodium_crypto_generichash_init($auth_key);
        // Number of pieces that go into MAC (header, first nonce, salt, ciphertext) -> 4
        if ($config->USE_PAE) {
            // Number of pieces:
            sodium_crypto_generichash_update($mac, pack('P', is_null($aad) ? 4 : 5));
            // Length followed by piece:
            sodium_crypto_generichash_update($mac, pack('P', Halite::VERSION_TAG_LEN));
            sodium_crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
            sodium_crypto_generichash_update($mac, pack('P', SODIUM_CRYPTO_STREAM_NONCEBYTES));
            sodium_crypto_generichash_update($mac, $first_nonce);
            sodium_crypto_generichash_update($mac, pack('P', $config->HKDF_SALT_LEN));
            sodium_crypto_generichash_update($mac, $hkdf_salt);
            if (!is_null($aad)) {
                sodium_crypto_generichash_update($mac, pack('P', Binary::safe_strlen($aad)));
                sodium_crypto_generichash_update($mac, pack('P', $aad));
            }
            sodium_crypto_generichash_update($mac, pack('P', $input->remaining_bytes()));
        } else {
            // Legacy version: No PAE
            sodium_crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
            sodium_crypto_generichash_update($mac, $first_nonce);
            sodium_crypto_generichash_update($mac, $hkdf_salt);
        }
        if (!is_string($mac)) {
            throw new Cannot_Perform_Operation('Internal error with BLAKE2b implementation');
        }
        Util::memzero($auth_key);
        Util::memzero($hkdf_salt);
        return self::stream_encrypt($input, $output, new Encryption_Key(new Hidden_String($enc_key)), $first_nonce, $mac, $config);
    }
    /**
     * Decrypt the contents of a file.
     *
     * @param string|null $aad    Additional authenticated data
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     */
    protected static function decrypt_data(Read_Only_File $input, Mutable_File $output, Encryption_Key $key, ?string $aad = null): bool
    {
        // Rewind
        $input->reset(0);
        // Make sure it's large enough to even read a version tag
        if ($input->get_size() < Halite::VERSION_TAG_LEN) {
            throw new Invalid_Message('Input file is too small to have been encrypted by Halite.');
        }
        // Parse the header, ensuring we get 4 bytes
        $header = $input->read_bytes(Halite::VERSION_TAG_LEN);
        // Load the config
        /** @var SymmetricConfig $config */
        $config = self::get_config($header, 'encrypt');
        // Is this shorter than an encrypted empty string?
        if ($input->get_size() < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new Invalid_Message('Input file is too small to have been encrypted by Halite.');
        }
        // Let's grab the first nonce and salt
        $first_nonce = $input->read_bytes((int) $config->NONCE_BYTES);
        $hkdf_salt = $input->read_bytes((int) $config->HKDF_SALT_LEN);
        // Split our keys, begin the HMAC instance
        [$enc_key, $auth_key] = Util::split_keys($key, $hkdf_salt, $config);
        // VERSION 2+ uses BMAC
        $mac = sodium_crypto_generichash_init($auth_key);
        if ($config->USE_PAE) {
            // Number of pieces:
            sodium_crypto_generichash_update($mac, pack('P', is_null($aad) ? 4 : 5));
            // Length followed by piece:
            sodium_crypto_generichash_update($mac, pack('P', Halite::VERSION_TAG_LEN));
            sodium_crypto_generichash_update($mac, $header);
            sodium_crypto_generichash_update($mac, pack('P', SODIUM_CRYPTO_STREAM_NONCEBYTES));
            sodium_crypto_generichash_update($mac, $first_nonce);
            sodium_crypto_generichash_update($mac, pack('P', $config->HKDF_SALT_LEN));
            sodium_crypto_generichash_update($mac, $hkdf_salt);
            if (!is_null($aad)) {
                sodium_crypto_generichash_update($mac, pack('P', Binary::safe_strlen($aad)));
                sodium_crypto_generichash_update($mac, pack('P', $aad));
            }
            sodium_crypto_generichash_update($mac, pack('P', $input->remaining_bytes() - (int) $config->MAC_SIZE));
        } else {
            // Legacy version: No PAE
            sodium_crypto_generichash_update($mac, $header);
            sodium_crypto_generichash_update($mac, $first_nonce);
            sodium_crypto_generichash_update($mac, $hkdf_salt);
        }
        if (!is_string($mac)) {
            throw new Cannot_Perform_Operation('Internal error with BLAKE2b implementation');
        }
        $old_macs = self::stream_verify($input, Util::safe_strcpy($mac), $config);
        Util::memzero($auth_key);
        Util::memzero($hkdf_salt);
        $ret = self::stream_decrypt($input, $output, new Encryption_Key(new Hidden_String($enc_key)), $first_nonce, $mac, $config, $old_macs);
        Util::memzero($enc_key);
        unset($enc_key);
        unset($auth_key);
        unset($first_nonce);
        unset($mac);
        unset($config);
        unset($old_macs);
        return $ret;
    }
    /**
     * Seal the contents of a file.
     *
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws Exception
     * @throws TypeError
     */
    protected static function seal_data(Read_Only_File $input, Mutable_File $output, Encryption_Public_Key $public_key, ?string $aad = null): int
    {
        // Generate a new keypair for this encryption
        $ephemeral_key_pair = Key_Factory::generate_encryption_key_pair();
        $eph_secret = $ephemeral_key_pair->get_secret_key();
        $eph_public = $ephemeral_key_pair->get_public_key();
        unset($ephemeral_key_pair);
        // Calculate the shared secret key
        $shared_secret_key = Asymmetric_Crypto::get_shared_secret($eph_secret, $public_key, true, Asymmetric_Crypto::get_asymmetric_config(Halite::HALITE_VERSION_FILE, true));
        // @codeCoverageIgnoreStart
        if (!$shared_secret_key instanceof Encryption_Key) {
            throw new TypeError('Shared secret is the wrong key type.');
        }
        // @codeCoverageIgnoreEnd
        // Destroy the secret key after we have the shared secret
        unset($eph_secret);
        // Load the configuration
        $config = self::get_config(Halite::HALITE_VERSION_FILE, 'seal');
        // Generate a nonce as per crypto_box_seal
        $nonce = sodium_crypto_generichash($eph_public->get_raw_key_material() . $public_key->get_raw_key_material(), '', SODIUM_CRYPTO_STREAM_NONCEBYTES);
        // Generate a random HKDF salt
        $hkdf_salt = random_bytes((int) $config->HKDF_SALT_LEN);
        // Split the keys
        /**
         * @var string $encKey
         * @var string $authKey
         */
        [$enc_key, $auth_key] = Util::split_keys($shared_secret_key, $hkdf_salt, $config);
        // Write the header:
        $output->write_bytes(Halite::HALITE_VERSION_FILE, Halite::VERSION_TAG_LEN);
        $output->write_bytes($eph_public->get_raw_key_material(), SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
        $output->write_bytes($hkdf_salt, (int) $config->HKDF_SALT_LEN);
        // VERSION 2+
        $mac = sodium_crypto_generichash_init($auth_key);
        Util::memzero($auth_key);
        if ($config->USE_PAE) {
            // Number of pieces:
            sodium_crypto_generichash_update($mac, pack('P', is_null($aad) ? 4 : 5));
            // Length followed by piece:
            sodium_crypto_generichash_update($mac, pack('P', Halite::VERSION_TAG_LEN));
            sodium_crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
            sodium_crypto_generichash_update($mac, pack('P', SODIUM_CRYPTO_BOX_PUBLICKEYBYTES));
            sodium_crypto_generichash_update($mac, $eph_public->get_raw_key_material());
            sodium_crypto_generichash_update($mac, pack('P', $config->HKDF_SALT_LEN));
            sodium_crypto_generichash_update($mac, $hkdf_salt);
            if (!is_null($aad)) {
                sodium_crypto_generichash_update($mac, pack('P', Binary::safe_strlen($aad)));
                sodium_crypto_generichash_update($mac, pack('P', $aad));
            }
            sodium_crypto_generichash_update($mac, pack('P', $input->remaining_bytes()));
        } else {
            // Legacy version: No PAE
            sodium_crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
            sodium_crypto_generichash_update($mac, $eph_public->get_raw_key_material());
            sodium_crypto_generichash_update($mac, $hkdf_salt);
        }
        if (!is_string($mac)) {
            throw new Cannot_Perform_Operation('Internal error with BLAKE2b implementation');
        }
        unset($eph_public);
        Util::memzero($hkdf_salt);
        $ret = self::stream_encrypt($input, $output, new Encryption_Key(new Hidden_String($enc_key)), $nonce, $mac, $config);
        Util::memzero($enc_key);
        unset($enc_key);
        unset($nonce);
        return $ret;
    }
    /**
     * Unseal the contents of a file.
     *
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws TypeError
     * @throws SodiumException
     */
    protected static function unseal_data(Read_Only_File $input, Mutable_File $output, Encryption_Secret_Key $secret_key, ?string $aad = null): bool
    {
        $public_key = $secret_key->derive_public_key();
        // Is the file at least as long as a header?
        if ($input->get_size() < Halite::VERSION_TAG_LEN) {
            throw new Invalid_Message('Input file is too small to have been encrypted by Halite.');
        }
        // Parse the header, ensuring we get 4 bytes
        $header = $input->read_bytes(Halite::VERSION_TAG_LEN);
        // Load the config
        $config = self::get_config($header, 'seal');
        if ($input->get_size() < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new Invalid_Message('Input file is too small to have been encrypted by Halite.');
        }
        // Let's grab the public key and salt
        $eph_public = $input->read_bytes((int) $config->PUBLICKEY_BYTES);
        $hkdf_salt = $input->read_bytes((int) $config->HKDF_SALT_LEN);
        // Generate the same nonce, as per sealData()
        $nonce = sodium_crypto_generichash($eph_public . $public_key->get_raw_key_material(), '', SODIUM_CRYPTO_STREAM_NONCEBYTES);
        // Create a key object out of the public key:
        $ephemeral = new Encryption_Public_Key(new Hidden_String($eph_public));
        $key = Asymmetric_Crypto::get_shared_secret($secret_key, $ephemeral, true, Asymmetric_Crypto::get_asymmetric_config($header, true));
        // @codeCoverageIgnoreStart
        if (!$key instanceof Encryption_Key) {
            throw new TypeError();
        }
        // @codeCoverageIgnoreEnd
        unset($ephemeral);
        /**
         * @var string $encKey
         * @var string $authKey
         */
        [$enc_key, $auth_key] = Util::split_keys($key, $hkdf_salt, $config);
        // We no longer need the original key after we split it
        unset($key);
        $mac = sodium_crypto_generichash_init($auth_key);
        if ($config->USE_PAE) {
            // Number of pieces:
            sodium_crypto_generichash_update($mac, pack('P', is_null($aad) ? 4 : 5));
            // Length followed by piece:
            sodium_crypto_generichash_update($mac, pack('P', Halite::VERSION_TAG_LEN));
            sodium_crypto_generichash_update($mac, $header);
            sodium_crypto_generichash_update($mac, pack('P', SODIUM_CRYPTO_BOX_PUBLICKEYBYTES));
            sodium_crypto_generichash_update($mac, $eph_public);
            sodium_crypto_generichash_update($mac, pack('P', $config->HKDF_SALT_LEN));
            sodium_crypto_generichash_update($mac, $hkdf_salt);
            if (!is_null($aad)) {
                sodium_crypto_generichash_update($mac, pack('P', Binary::safe_strlen($aad)));
                sodium_crypto_generichash_update($mac, pack('P', $aad));
            }
            sodium_crypto_generichash_update($mac, pack('P', $input->remaining_bytes() - (int) $config->MAC_SIZE));
        } else {
            // Legacy version: No PAE
            sodium_crypto_generichash_update($mac, $header);
            sodium_crypto_generichash_update($mac, $eph_public);
            sodium_crypto_generichash_update($mac, $hkdf_salt);
        }
        if (!is_string($mac)) {
            throw new Cannot_Perform_Operation('Internal error with BLAKE2b implementation');
        }
        $old_ma_cs = self::stream_verify($input, Util::safe_strcpy($mac), $config);
        // We no longer need these:
        Util::memzero($auth_key);
        Util::memzero($hkdf_salt);
        $ret = self::stream_decrypt($input, $output, new Encryption_Key(new Hidden_String($enc_key)), $nonce, $mac, $config, $old_ma_cs);
        Util::memzero($enc_key);
        unset($enc_key);
        unset($nonce);
        unset($mac);
        unset($config);
        unset($old_ma_cs);
        return $ret;
    }
    /**
     * Sign the contents of a file
     *
     * @param string|bool $encoding Which encoding scheme to use for the signature?
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws TypeError
     */
    protected static function sign_data(Read_Only_File $input, Signature_Secret_Key $secret_key, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE): string
    {
        $checksum = self::checksum_data($input, $secret_key->derive_public_key(), true);
        return Asymmetric_Crypto::sign($checksum, $secret_key, $encoding);
    }
    /**
     * Verify the contents of a file
     *
     * @param $input (file handle)
     * @param string|bool $encoding Which encoding scheme to use for the signature?
     *
     *
     * @throws InvalidSignature
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    protected static function verify_data(Read_Only_File $input, Signature_Public_Key $public_key, string $signature, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE): bool
    {
        $checksum = self::checksum_data($input, $public_key, true);
        return Asymmetric_Crypto::verify($checksum, $public_key, $signature, $encoding);
    }
    /**
     * Get the configuration
     *
     * @throws InvalidMessage
     * @throws InvalidType
     */
    protected static function get_config(string $header, string $mode = 'encrypt'): \Paragon_Ie\Halite\Symmetric\Config
    {
        if (Util::chr_to_int($header[0]) !== 49 || Util::chr_to_int($header[1]) !== 65) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Message('Invalid version tag');
            // @codeCoverageIgnoreEnd
        }
        $major = Util::chr_to_int($header[2]);
        $minor = Util::chr_to_int($header[3]);
        if ($mode === 'encrypt') {
            return new Symmetric_Config(self::get_config_encrypt($major, $minor));
        }
        if ($mode === 'seal') {
            return new Symmetric_Config(self::get_config_seal($major, $minor));
        }
        if ($mode === 'checksum') {
            return new Symmetric_Config(self::get_config_checksum($major, $minor));
        }
        // @codeCoverageIgnoreStart
        throw new Invalid_Type('Invalid configuration mode');
        // @codeCoverageIgnoreEnd
    }
    /**
     * Get the configuration for encrypt operations
     *
     * @throws InvalidMessage
     */
    protected static function get_config_encrypt(int $major, int $minor): array
    {
        if ($major === 5) {
            return ['SHORTEST_CIPHERTEXT_LENGTH' => 92, 'BUFFER' => 1048576, 'NONCE_BYTES' => SODIUM_CRYPTO_STREAM_NONCEBYTES, 'HKDF_SALT_LEN' => 32, 'MAC_SIZE' => 32, 'ENC_ALGO' => 'XChaCha20', 'USE_PAE' => true, 'HKDF_USE_INFO' => true, 'HKDF_SBOX' => 'Halite|EncryptionKey', 'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'];
        }
        if ($major === 4) {
            return ['SHORTEST_CIPHERTEXT_LENGTH' => 92, 'BUFFER' => 1048576, 'NONCE_BYTES' => SODIUM_CRYPTO_STREAM_NONCEBYTES, 'HKDF_SALT_LEN' => 32, 'MAC_SIZE' => 32, 'ENC_ALGO' => 'XSalsa20', 'USE_PAE' => false, 'HKDF_USE_INFO' => false, 'HKDF_SBOX' => 'Halite|EncryptionKey', 'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'];
        }
        // If we reach here, we've got an invalid version tag:
        // @codeCoverageIgnoreStart
        throw new Invalid_Message('Invalid version tag');
        // @codeCoverageIgnoreEnd
    }
    /**
     * Get the configuration for seal operations
     *
     * @throws InvalidMessage
     */
    protected static function get_config_seal(int $major, int $minor): array
    {
        if ($major === 5) {
            switch ($minor) {
                case 0:
                    return ['SHORTEST_CIPHERTEXT_LENGTH' => 100, 'BUFFER' => 1048576, 'HKDF_SALT_LEN' => 32, 'MAC_SIZE' => 32, 'PUBLICKEY_BYTES' => SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'ENC_ALGO' => 'XChaCha20', 'USE_PAE' => true, 'HKDF_USE_INFO' => true, 'HKDF_SBOX' => 'Halite|EncryptionKey', 'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'];
            }
        } elseif ($major === 4) {
            switch ($minor) {
                case 0:
                    return ['SHORTEST_CIPHERTEXT_LENGTH' => 100, 'BUFFER' => 1048576, 'HKDF_SALT_LEN' => 32, 'MAC_SIZE' => 32, 'PUBLICKEY_BYTES' => SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'ENC_ALGO' => 'XSalsa20', 'USE_PAE' => false, 'HKDF_USE_INFO' => false, 'HKDF_SBOX' => 'Halite|EncryptionKey', 'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'];
            }
        }
        // @codeCoverageIgnoreStart
        throw new Invalid_Message('Invalid version tag');
        // @codeCoverageIgnoreEnd
    }
    /**
     * Get the configuration for encrypt operations
     *
     * @throws InvalidMessage
     */
    protected static function get_config_checksum(int $major, int $minor): array
    {
        if ($major === 3 || $major === 4 || $major === 5) {
            switch ($minor) {
                case 0:
                    return ['CHECKSUM_PUBKEY' => true, 'BUFFER' => 1048576, 'HASH_LEN' => SODIUM_CRYPTO_GENERICHASH_BYTES_MAX];
            }
        }
        // @codeCoverageIgnoreStart
        throw new Invalid_Message('Invalid version tag');
        // @codeCoverageIgnoreEnd
    }
    /**
     * Stream encryption - Do not call directly
     *
     * @param string $mac (hash context for BLAKE2b)
     *
     * @return int (number of bytes)
     *
     * @throws FileError
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws SodiumException
     * @throws TypeError
     */
    private static function stream_encrypt(Read_Only_File $input, Mutable_File $output, Encryption_Key $enc_key, string $nonce, string $mac, Config $config): int
    {
        $init_hash = $input->get_hash();
        // Begin the streaming decryption
        $size = $input->get_size();
        $written = 0;
        while ($input->remaining_bytes() > 0) {
            $read = $input->read_bytes($input->get_pos() + (int) $config->BUFFER > $size ? $size - $input->get_pos() : (int) $config->BUFFER);
            if ($config->ENC_ALGO === 'XChaCha20') {
                $encrypted = sodium_crypto_stream_xchacha20_xor($read, (string) $nonce, $enc_key->get_raw_key_material());
            } else {
                $encrypted = sodium_crypto_stream_xor($read, (string) $nonce, $enc_key->get_raw_key_material());
            }
            sodium_crypto_generichash_update($mac, $encrypted);
            $written += $output->write_bytes($encrypted);
            sodium_increment($nonce);
        }
        if (is_string($nonce)) {
            Util::memzero($nonce);
        }
        // Check that our input file was not modified before we MAC it
        if (!hash_equals($input->get_hash(), $init_hash)) {
            // @codeCoverageIgnoreStart
            throw new File_Modified('Read-only file has been modified since it was opened for reading');
            // @codeCoverageIgnoreEnd
        }
        return $written + $output->write_bytes(sodium_crypto_generichash_final($mac, (int) $config->MAC_SIZE), (int) $config->MAC_SIZE);
    }
    /**
     * Stream decryption - Do not call directly
     *
     * @param string $mac (hash context for BLAKE2b)
     * @param string[] &$chunk_macs
     *
     *
     * @throws FileError
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidMessage
     * @throws TypeError
     * @throws SodiumException
     */
    private static function stream_decrypt(Read_Only_File $input, Mutable_File $output, Encryption_Key $enc_key, string $nonce, string $mac, Config $config, array &$chunk_macs): bool
    {
        $start = $input->get_pos();
        $cipher_end = $input->get_size() - (int) $config->MAC_SIZE;
        // Begin the streaming decryption
        $input->reset($start);
        while ($input->remaining_bytes() > (int) $config->MAC_SIZE) {
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if ($input->get_pos() + (int) $config->BUFFER > $cipher_end) {
                $read = $input->read_bytes($cipher_end - $input->get_pos());
            } else {
                // @codeCoverageIgnoreStart
                $read = $input->read_bytes((int) $config->BUFFER);
                // @codeCoverageIgnoreEnd
            }
            // Version 2+ uses a keyed BLAKE2b hash instead of HMAC
            sodium_crypto_generichash_update($mac, $read);
            if (!is_string($mac)) {
                throw new Cannot_Perform_Operation('Internal error with BLAKE2b implementation');
            }
            $calc_mac = Util::safe_strcpy($mac);
            $calc = sodium_crypto_generichash_final($calc_mac, (int) $config->MAC_SIZE);
            if (empty($chunk_macs)) {
                // @codeCoverageIgnoreStart
                // Someone attempted to add a chunk at the end.
                throw new Invalid_Message('Invalid message authentication code');
                // @codeCoverageIgnoreEnd
            } else {
                $chunk_mac = array_shift($chunk_macs);
                if (!hash_equals($chunk_mac, $calc)) {
                    // This chunk was altered after the original MAC was verified
                    // @codeCoverageIgnoreStart
                    throw new Invalid_Message('Invalid message authentication code');
                    // @codeCoverageIgnoreEnd
                }
            }
            // This is where the decryption actually occurs:
            if ($config->ENC_ALGO === 'XChaCha20') {
                $decrypted = sodium_crypto_stream_xchacha20_xor($read, (string) $nonce, $enc_key->get_raw_key_material());
            } else {
                $decrypted = sodium_crypto_stream_xor($read, (string) $nonce, $enc_key->get_raw_key_material());
            }
            $output->write_bytes($decrypted);
            sodium_increment($nonce);
        }
        if (is_string($nonce)) {
            Util::memzero($nonce);
        }
        return true;
    }
    /**
     * Recalculate and verify the HMAC of the input file
     *
     * @param ReadOnlyFile $input  The file we are verifying
     * @param string $mac          (hash context)
     * @param Config $config       Version-specific settings
     *
     * @return string[]            Hashes of various chunks
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidMessage
     * @throws TypeError
     * @throws SodiumException
     */
    private static function stream_verify(Read_Only_File $input, string $mac, Config $config): array
    {
        $start = $input->get_pos();
        // Grab the stored MAC:
        $cipher_end = $input->get_size() - (int) $config->MAC_SIZE;
        $input->reset($cipher_end);
        $stored_mac = $input->read_bytes((int) $config->MAC_SIZE);
        $input->reset($start);
        $chunk_ma_cs = [];
        $break = false;
        while (!$break && $input->get_pos() < $cipher_end) {
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if ($input->get_pos() + (int) $config->BUFFER >= $cipher_end) {
                $break = true;
                $read = $input->read_bytes($cipher_end - $input->get_pos());
            } else {
                // @codeCoverageIgnoreStart
                $read = $input->read_bytes((int) $config->BUFFER);
                // @codeCoverageIgnoreEnd
            }
            /**
             * We're updating our HMAC and nothing else
             */
            sodium_crypto_generichash_update($mac, $read);
            if (!is_string($mac)) {
                throw new Cannot_Perform_Operation('Internal error with BLAKE2b implementation');
            }
            // Copy the hash state then store the MAC of this chunk
            $chunk_mac = Util::safe_strcpy($mac);
            $chunk_ma_cs[] = sodium_crypto_generichash_final(
                // @codeCoverageIgnoreStart
                $chunk_mac,
                // @codeCoverageIgnoreEnd
                (int) $config->MAC_SIZE
            );
        }
        /**
         * We should now have enough data to generate an identical MAC
         */
        $final_hmac = sodium_crypto_generichash_final(
            // @codeCoverageIgnoreStart
            $mac,
            // @codeCoverageIgnoreEnd
            (int) $config->MAC_SIZE
        );
        /**
         * Use hash_equals() to be timing-invariant
         */
        if (!hash_equals($final_hmac, $stored_mac)) {
            throw new Invalid_Message('Invalid message authentication code');
        }
        $input->reset($start);
        return $chunk_ma_cs;
    }
}