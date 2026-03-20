<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Error;
use function is_string;
use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\{Halite, Key, Symmetric\Crypto as SymmetricCrypto, Symmetric\Encryption_Key, Util};
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Digest_Length, Invalid_Key, Invalid_Message, Invalid_Signature, Invalid_Type};
use Paragon_Ie\Hidden_String\Hidden_String;
use RangeException;
use function sodium_crypto_box_keypair_from_secretkey_and_publickey;
use function sodium_crypto_box_publickey_from_secretkey;
use function sodium_crypto_box_seal;
use function sodium_crypto_box_seal_open;
use function sodium_crypto_scalarmult;
use const SODIUM_CRYPTO_SIGN_BYTES;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;
use const SODIUM_CRYPTO_STREAM_KEYBYTES;
use Sodium_Exception;
use TypeError;
/**
 * Class Crypto
 *
 * Handles all public key cryptography
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Asymmetric
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
     * Encrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::encrypt()
     *
     * @param HiddenString $plaintext              The message to encrypt
     * @param EncryptionSecretKey $ourPrivateKey   Our private key
     * @param EncryptionPublicKey $theirPublicKey  Their public key
     * @param string|bool $encoding                Which encoding scheme to use?
     * @return string                              Ciphertext
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidDigestLength
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encrypt(
        #[\Sensitive_Parameter]
        Hidden_String $plaintext,
        #[\Sensitive_Parameter]
        Encryption_Secret_Key $our_private_key,
        Encryption_Public_Key $their_public_key,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string
    {
        return self::encrypt_with_ad($plaintext, $our_private_key, $their_public_key, '', $encoding);
    }
    /**
     * Encrypt with additional associated data.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidDigestLength
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encrypt_with_ad(
        #[\Sensitive_Parameter]
        Hidden_String $plaintext,
        #[\Sensitive_Parameter]
        Encryption_Secret_Key $our_private_key,
        Encryption_Public_Key $their_public_key,
        #[\Sensitive_Parameter]
        string $additional_data = '',
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string
    {
        /** @var HiddenString $ss */
        $ss = self::get_shared_secret($our_private_key, $their_public_key, false, self::get_asymmetric_config(Halite::HALITE_VERSION, true));
        $shared_secret_key = new Encryption_Key($ss);
        $ciphertext = Symmetric_Crypto::encrypt_with_ad($plaintext, $shared_secret_key, $additional_data, $encoding);
        unset($shared_secret_key);
        return $ciphertext;
    }
    /**
     * Decrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::decrypt()
     *
     * @param string $ciphertext                  The message to decrypt
     * @param EncryptionSecretKey $ourPrivateKey  Our private key
     * @param EncryptionPublicKey $theirPublicKey Their public key
     * @param string|bool $encoding               Which encoding scheme to use?
     * @return HiddenString                       The decrypted message
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decrypt(
        string $ciphertext,
        #[\Sensitive_Parameter]
        Encryption_Secret_Key $our_private_key,
        Encryption_Public_Key $their_public_key,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): Hidden_String
    {
        return self::decrypt_with_ad($ciphertext, $our_private_key, $their_public_key, '', $encoding);
    }
    /**
     * Decrypt with additional associated data.
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decrypt_with_ad(
        string $ciphertext,
        #[\Sensitive_Parameter]
        Encryption_Secret_Key $our_private_key,
        Encryption_Public_Key $their_public_key,
        #[\Sensitive_Parameter]
        string $additional_data = '',
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): Hidden_String
    {
        /** @var HiddenString $ss */
        $ss = self::get_shared_secret($our_private_key, $their_public_key, false, self::get_asymmetric_config($ciphertext, $encoding));
        $shared_secret_key = new Encryption_Key($ss);
        $plaintext = Symmetric_Crypto::decrypt_with_ad($ciphertext, $shared_secret_key, $additional_data, $encoding);
        unset($shared_secret_key);
        return $plaintext;
    }
    /**
     * Diffie-Hellman, ECDHE, etc.
     *
     * Get a shared secret from a private key you possess and a public key for
     * the intended message recipient
     *
     * @param EncryptionSecretKey $privateKey Private key (yours)
     * @param EncryptionPublicKey $publicKey  Public key (theirs)
     * @param bool $get_as_object             Get as a Key object?
     * @param ?Config $config                 Asymmetric Config
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function get_shared_secret(
        #[\Sensitive_Parameter]
        Encryption_Secret_Key $private_key,
        Encryption_Public_Key $public_key,
        bool $get_as_object = false,
        ?Config $config = null
    ): Hidden_String|Key
    {
        if (!is_null($config)) {
            if ($config->HASH_SCALARMULT) {
                $hidden_string = new Hidden_String(Util::hkdf_blake2b(sodium_crypto_scalarmult($private_key->get_raw_key_material(), $public_key->get_raw_key_material()), SODIUM_CRYPTO_STREAM_KEYBYTES, (string) $config->HASH_DOMAIN_SEPARATION));
                if ($get_as_object) {
                    return new Encryption_Key($hidden_string);
                }
                return $hidden_string;
            }
        }
        $hidden_string = new Hidden_String(sodium_crypto_scalarmult($private_key->get_raw_key_material(), $public_key->get_raw_key_material()));
        if ($get_as_object) {
            return new Encryption_Key($hidden_string);
        }
        return $hidden_string;
    }
    /**
     * Encrypt a message with a target users' public key
     *
     * @param HiddenString $plaintext        Message to encrypt
     * @param EncryptionPublicKey $publicKey Public encryption key
     * @param string|bool $encoding          Which encoding scheme to use?
     *
     * @return string                        Ciphertext
     *
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function seal(
        #[\Sensitive_Parameter]
        Hidden_String $plaintext,
        Encryption_Public_Key $public_key,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string
    {
        $sealed = sodium_crypto_box_seal($plaintext->get_string(), $public_key->get_raw_key_material());
        $encoder = Halite::choose_encoder($encoding);
        if ($encoder) {
            return (string) $encoder($sealed);
        }
        return $sealed;
    }
    /**
     * Sign a message with our private key
     *
     * @param string $message                Message to sign
     * @param SignatureSecretKey $privateKey Private signing key
     * @param string|bool $encoding          Which encoding scheme to use?
     *
     * @return string Signature (detached)
     *
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sign(
        string $message,
        #[\Sensitive_Parameter]
        Signature_Secret_Key $private_key,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string
    {
        $signed = sodium_crypto_sign_detached($message, $private_key->get_raw_key_material());
        $encoder = Halite::choose_encoder($encoding);
        if ($encoder) {
            return (string) $encoder($signed);
        }
        return $signed;
    }
    /**
     * Sign a message then encrypt it with the recipient's public key.
     *
     * @param HiddenString $message           Plaintext message to sign and encrypt
     * @param SignatureSecretKey $secretKey   Private signing key
     * @param PublicKey $recipientPublicKey   Public encryption key
     * @param string|bool $encoding           Which encoding scheme to use?
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sign_and_encrypt(
        Hidden_String $message,
        #[\Sensitive_Parameter]
        Signature_Secret_Key $secret_key,
        Public_Key $recipient_public_key,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string
    {
        if ($recipient_public_key instanceof Signature_Public_Key) {
            $public_key = $recipient_public_key->get_encryption_public_key();
        } elseif ($recipient_public_key instanceof Encryption_Public_Key) {
            $public_key = $recipient_public_key;
        } else {
            // @codeCoverageIgnoreStart
            throw new Invalid_Key('An invalid key type was provided');
            // @codeCoverageIgnoreEnd
        }
        $signature = self::sign($message->get_string(), $secret_key, true);
        $plaintext = new Hidden_String($signature . $message->get_string());
        Util::memzero($signature);
        $my_enc_key = $secret_key->get_encryption_secret_key();
        return self::encrypt($plaintext, $my_enc_key, $public_key, $encoding);
    }
    /**
     * Decrypt a sealed message with our private key
     *
     * @param string $ciphertext              Encrypted message
     * @param EncryptionSecretKey $privateKey Private decryption key
     * @param string|bool $encoding           Which encoding scheme to use?
     *
     *
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function unseal(
        string $ciphertext,
        #[\Sensitive_Parameter]
        Encryption_Secret_Key $private_key,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): Hidden_String
    {
        $decoder = Halite::choose_encoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            try {
                /** @var string $ciphertext */
                $ciphertext = $decoder($ciphertext);
            } catch (RangeException) {
                throw new Invalid_Message('Invalid character encoding');
            }
        }
        // Get a box keypair (needed by crypto_box_seal_open)
        $secret_key = $private_key->get_raw_key_material();
        $public_key = sodium_crypto_box_publickey_from_secretkey($secret_key);
        $key_pair = sodium_crypto_box_keypair_from_secretkey_and_publickey($secret_key, $public_key);
        // Wipe these immediately:
        Util::memzero($secret_key);
        Util::memzero($public_key);
        // Now let's open that sealed box
        $message = sodium_crypto_box_seal_open($ciphertext, $key_pair);
        // Always memzero after retrieving a value
        Util::memzero($key_pair);
        if (!is_string($message)) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Key('Incorrect secret key for this sealed message');
            // @codeCoverageIgnoreEnd
        }
        // We have our encrypted message here
        return new Hidden_String($message);
    }
    /**
     * Verify a signed message with the correct public key
     *
     * @param string $message               Message to verify
     * @param SignaturePublicKey $publicKey Public key
     * @param string $signature             Signature
     * @param string|bool $encoding         Which encoding scheme to use?
     *
     *
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify(string $message, Signature_Public_Key $public_key, string $signature, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE): bool
    {
        $decoder = Halite::choose_encoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            /** @var string $signature */
            $signature = $decoder($signature);
        }
        if (Binary::safe_strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            // @codeCoverageIgnoreStart
            throw new Invalid_Signature('Signature is not the correct length; is it encoded?');
            // @codeCoverageIgnoreEnd
        }
        return sodium_crypto_sign_verify_detached($signature, $message, $public_key->get_raw_key_material());
    }
    /**
     * Decrypt a message, then verify its signature.
     *
     * @param string $ciphertext                   Plaintext message to sign and encrypt
     * @param SignaturePublicKey $senderPublicKey  Private signing key
     * @param SecretKey $givenSecretKey            Public encryption key
     * @param string|bool $encoding                Which encoding scheme to use?
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify_and_decrypt(
        string $ciphertext,
        Signature_Public_Key $sender_public_key,
        #[\Sensitive_Parameter]
        Secret_Key $given_secret_key,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): Hidden_String
    {
        if ($given_secret_key instanceof Signature_Secret_Key) {
            $secret_key = $given_secret_key->get_encryption_secret_key();
        } elseif ($given_secret_key instanceof Encryption_Secret_Key) {
            $secret_key = $given_secret_key;
        } else {
            throw new Invalid_Key('An invalid key type was provided');
        }
        $sender_enc_key = $sender_public_key->get_encryption_public_key();
        $decrypted = self::decrypt($ciphertext, $secret_key, $sender_enc_key, $encoding);
        $signature = Binary::safe_substr($decrypted->get_string(), 0, SODIUM_CRYPTO_SIGN_BYTES);
        $message = Binary::safe_substr($decrypted->get_string(), SODIUM_CRYPTO_SIGN_BYTES);
        if (!self::verify($message, $sender_public_key, $signature, true)) {
            throw new Invalid_Signature('Invalid signature for decrypted message');
        }
        return new Hidden_String($message);
    }
    /**
     * Get the Asymmetric configuration expected for this Halite version
     *
     *
     *
     * @throws InvalidMessage
     * @throws InvalidType
     */
    public static function get_asymmetric_config(string $ciphertext, string|bool $encoding = Halite::ENCODE_BASE64URLSAFE): Config
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
        $version = Binary::safe_substr($ciphertext, 0, Halite::VERSION_TAG_LEN);
        return Config::get_config($version);
    }
}