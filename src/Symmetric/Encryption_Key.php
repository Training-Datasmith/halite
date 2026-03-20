<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Symmetric;

use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\Alerts\Invalid_Key;
use Paragon_Ie\Hidden_String\Hidden_String;
use const SODIUM_CRYPTO_STREAM_KEYBYTES;
use function sprintf;
use TypeError;
/**
 * Class EncryptionKey
 * @package ParagonIE\Halite\Symmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Encryption_Key extends Secret_Key
{
    /**
     * EncryptionKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(
        #[\Sensitive_Parameter]
        Hidden_String $key_material
    )
    {
        if (Binary::safe_strlen($key_material->get_string()) !== SODIUM_CRYPTO_STREAM_KEYBYTES) {
            throw new Invalid_Key(sprintf('Encryption key must be CRYPTO_STREAM_KEYBYTES (%d) bytes long', SODIUM_CRYPTO_STREAM_KEYBYTES));
        }
        parent::__construct($key_material);
    }
}