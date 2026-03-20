<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\Alerts\Invalid_Key;
use Paragon_Ie\Hidden_String\Hidden_String;
use function sodium_crypto_box_publickey_from_secretkey;
use const SODIUM_CRYPTO_BOX_SECRETKEYBYTES;
use Sodium_Exception;
use function sprintf;
use TypeError;
/**
 * Class EncryptionSecretKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Encryption_Secret_Key extends Secret_Key
{
    /**
     * EncryptionSecretKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(
        #[\Sensitive_Parameter]
        Hidden_String $key_material,
        ?Hidden_String $pk = null
    )
    {
        if (Binary::safe_strlen($key_material->get_string()) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new Invalid_Key(sprintf('Encryption secret key must be CRYPTO_BOX_SECRETKEYBYTES (%d) bytes long', SODIUM_CRYPTO_BOX_SECRETKEYBYTES));
        }
        parent::__construct($key_material, $pk);
    }
    /**
     * See the appropriate derived class.
     *
     *
     * @throws InvalidKey
     * @throws TypeError
     * @throws SodiumException
     */
    public function derive_public_key(): Encryption_Public_Key
    {
        if (is_null($this->cached_public_key)) {
            $this->cached_public_key = sodium_crypto_box_publickey_from_secretkey($this->get_raw_key_material());
        }
        return new Encryption_Public_Key(new Hidden_String($this->cached_public_key));
    }
}