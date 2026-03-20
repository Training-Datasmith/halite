<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use function count;
use InvalidArgumentException;
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Key};
use Paragon_Ie\Halite\Asymmetric\{Public_Key, Secret_Key, Signature_Public_Key, Signature_Secret_Key};
use Paragon_Ie\Hidden_String\Hidden_String;
use Sodium_Exception;
use TypeError;
/**
 * Class SignatureKeyPair
 *
 * Describes a pair of secret and public keys
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
final class Signature_Key_Pair extends Key_Pair
{
    /**
     * @var SignatureSecretKey
     */
    protected Secret_Key $secret_key;
    /**
     * @var SignaturePublicKey
     */
    protected Public_Key $public_key;
    /**
     * Pass it a secret key, it will automatically generate a public key
     *
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws TypeError
     */
    public function __construct(Key ...$keys)
    {
        switch (count($keys)) {
            /**
             * If we received two keys, it must be an asymmetric secret key and
             * an asymmetric public key, in either order.
             */
            case 2:
                if (!$keys[0]->is_asymmetric_key() || !$keys[1]->is_asymmetric_key()) {
                    throw new Invalid_Key('Only keys intended for asymmetric cryptography can be used in a KeyPair object');
                }
                if ($keys[0]->is_public_key()) {
                    if ($keys[1]->is_public_key()) {
                        throw new Invalid_Key('Both keys cannot be public keys');
                    }
                    $this->setup_key_pair(
                        // @codeCoverageIgnoreStart
                        $keys[1] instanceof Signature_Secret_Key ? $keys[1] : new Signature_Secret_Key(new Hidden_String($keys[1]->get_raw_key_material()))
                    );
                } elseif ($keys[1]->is_public_key()) {
                    $this->setup_key_pair(
                        // @codeCoverageIgnoreStart
                        $keys[0] instanceof Signature_Secret_Key ? $keys[0] : new Signature_Secret_Key(new Hidden_String($keys[0]->get_raw_key_material()))
                    );
                } else {
                    throw new Invalid_Key('Both keys cannot be secret keys');
                }
                break;
            /**
             * If we only received one key, it must be an asymmetric secret key!
             */
            case 1:
                if (!$keys[0]->is_asymmetric_key()) {
                    throw new Invalid_Key('Only keys intended for asymmetric cryptography can be used in a KeyPair object');
                }
                if ($keys[0]->is_public_key()) {
                    // Ever heard of the Elliptic Curve Discrete Logarithm Problem?
                    throw new Invalid_Key('We cannot generate a valid keypair given only a public key; we can given only a secret key, however.');
                }
                $this->setup_key_pair(
                    // @codeCoverageIgnoreStart
                    $keys[0] instanceof Signature_Secret_Key ? $keys[0] : new Signature_Secret_Key(new Hidden_String($keys[0]->get_raw_key_material()))
                );
                break;
            default:
                throw new InvalidArgumentException('EncryptionKeyPair expects 1 or 2 keys');
        }
    }
    /**
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public function get_encryption_key_pair(): Encryption_Key_Pair
    {
        return new Encryption_Key_Pair($this->secret_key->get_encryption_secret_key(), $this->public_key->get_encryption_public_key());
    }
    /**
     * Set up our key pair
     *
     *
     * @throws InvalidKey
     * @throws SodiumException
     */
    protected function setup_key_pair(
        #[\Sensitive_Parameter]
        Signature_Secret_Key $secret
    ): void
    {
        $this->secret_key = $secret;
        $this->public_key = $this->secret_key->derive_public_key();
    }
    /**
     * Get a Key object for the public key
     *
     * @return SignaturePublicKey
     */
    public function get_public_key(): \Paragon_Ie\Halite\Asymmetric\Public_Key
    {
        return $this->public_key;
    }
    /**
     * Get a Key object for the public key
     *
     * @return SignatureSecretKey
     */
    public function get_secret_key(): \Paragon_Ie\Halite\Asymmetric\Secret_Key
    {
        return $this->secret_key;
    }
}