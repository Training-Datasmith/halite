<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\Alerts\Invalid_Key;
use Paragon_Ie\Hidden_String\Hidden_String;
use function sodium_crypto_sign_ed25519_pk_to_curve25519;
use const SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;
use Sodium_Exception;
use function sprintf;
use TypeError;
/**
 * Class SignaturePublicKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Signature_Public_Key extends Public_Key
{
    /**
     * SignaturePublicKey constructor.
     *
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(Hidden_String $key_material)
    {
        if (Binary::safe_strlen($key_material->get_string()) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new Invalid_Key(sprintf('Signature public key must be CRYPTO_SIGN_PUBLICKEYBYTES (%d) bytes long', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES));
        }
        parent::__construct($key_material);
        $this->is_signing_key = true;
    }
    /**
     * Get an encryption public key from a signing public key.
     *
     *
     * @throws SodiumException
     * @throws TypeError
     * @throws InvalidKey
     */
    public function get_encryption_public_key(): Encryption_Public_Key
    {
        $ed25519_pk = $this->get_raw_key_material();
        $x25519_pk = sodium_crypto_sign_ed25519_pk_to_curve25519($ed25519_pk);
        return new Encryption_Public_Key(new Hidden_String($x25519_pk));
    }
}