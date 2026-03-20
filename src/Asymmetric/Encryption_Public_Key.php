<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\Alerts\Invalid_Key;
use Paragon_Ie\Hidden_String\Hidden_String;
use const SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
use function sprintf;
/**
 * Class EncryptionPublicKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Encryption_Public_Key extends Public_Key
{
    /**
     * EncryptionPublicKey constructor.
     *
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws InvalidKey
     * @throws \TypeError
     */
    public function __construct(Hidden_String $key_material)
    {
        if (Binary::safe_strlen($key_material->get_string()) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new Invalid_Key(sprintf('Encryption public key must be CRYPTO_BOX_PUBLICKEYBYTES (%d) bytes long', SODIUM_CRYPTO_BOX_PUBLICKEYBYTES));
        }
        parent::__construct($key_material);
    }
}