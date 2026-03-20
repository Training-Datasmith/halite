<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\Alerts\Invalid_Key;
use Paragon_Ie\Hidden_String\Hidden_String;
use function sodium_crypto_sign_ed25519_pk_to_curve25519;
use function sodium_crypto_sign_ed25519_sk_to_curve25519;
use function sodium_crypto_sign_publickey_from_secretkey;
use const SODIUM_CRYPTO_SIGN_SECRETKEYBYTES;
use Sodium_Exception;
use function sprintf;
use TypeError;
/**
 * Class SignatureSecretKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Signature_Secret_Key extends Secret_Key
{
    /**
     * SignatureSecretKey constructor.
     *
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(
        #[\Sensitive_Parameter]
        Hidden_String $key_material,
        ?Hidden_String $pk = null
    )
    {
        if (Binary::safe_strlen($key_material->get_string()) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new Invalid_Key(sprintf('Signature secret key must be CRYPTO_SIGN_SECRETKEYBYTES (%d) bytes long', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES));
        }
        parent::__construct($key_material, $pk);
        $this->is_signing_key = true;
    }
    /**
     * See the appropriate derived class.
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public function derive_public_key(): Signature_Public_Key
    {
        if (is_null($this->cached_public_key)) {
            $this->cached_public_key = sodium_crypto_sign_publickey_from_secretkey($this->get_raw_key_material());
        }
        return new Signature_Public_Key(new Hidden_String($this->cached_public_key));
    }
    /**
     * Get an encryption secret key from a signing secret key.
     *
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public function get_encryption_secret_key(): Encryption_Secret_Key
    {
        $ed25519_sk = $this->get_raw_key_material();
        $x25519_sk = sodium_crypto_sign_ed25519_sk_to_curve25519($ed25519_sk);
        if (!is_null($this->cached_public_key)) {
            $x25519_pk = sodium_crypto_sign_ed25519_pk_to_curve25519($this->cached_public_key);
            return new Encryption_Secret_Key(new Hidden_String($x25519_sk), new Hidden_String($x25519_pk));
        }
        return new Encryption_Secret_Key(new Hidden_String($x25519_sk));
    }
}