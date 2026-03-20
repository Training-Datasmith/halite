<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Paragon_Ie\Halite\Key;
use Paragon_Ie\Hidden_String\Hidden_String;
use TypeError;
/**
 * Class PublicKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
class Public_Key extends Key
{
    /**
     * PublicKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws TypeError
     */
    public function __construct(Hidden_String $key_material)
    {
        parent::__construct($key_material);
        $this->is_asymmetric_key = true;
        $this->is_public_key = true;
    }
}