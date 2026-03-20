<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Paragon_Ie\Halite\Alerts\Cannot_Perform_Operation;
use Paragon_Ie\Halite\Key;
use Paragon_Ie\Hidden_String\Hidden_String;
use TypeError;
/**
 * Class SecretKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
class Secret_Key extends Key
{
    protected ?string $cached_public_key = null;
    /**
     * SecretKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws TypeError
     */
    public function __construct(
        #[\Sensitive_Parameter]
        Hidden_String $key_material,
        ?Hidden_String $pk = null
    )
    {
        parent::__construct($key_material);
        if (!is_null($pk)) {
            $this->cached_public_key = $pk->get_string();
        }
        $this->is_asymmetric_key = true;
    }
    /**
     * See the appropriate derived class.
     * @throws CannotPerformOperation
     * @codeCoverageIgnore
     */
    public function derive_public_key(): Public_Key
    {
        throw new Cannot_Perform_Operation('This is not implemented in the base class');
    }
}