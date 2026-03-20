<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use Paragon_Ie\Halite\Asymmetric\{Public_Key, Secret_Key};
/**
 * Class KeyPair
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
class Key_Pair
{
    protected Secret_Key $secret_key;
    protected Public_Key $public_key;
    /**
     * Hide this from var_dump(), etc.
     *
     * @return array
     * @codeCoverageIgnore
     */
    public function __debugInfo()
    {
        return ['privateKey' => '**protected**', 'publicKey' => '**protected**'];
    }
    /**
     * Get a Key object for the public key
     *
     * @codeCoverageIgnore
     */
    public function get_public_key(): \Paragon_Ie\Halite\Asymmetric\Public_Key
    {
        return $this->public_key;
    }
    /**
     * Get a Key object for the secret key
     *
     * @codeCoverageIgnore
     */
    public function get_secret_key(): \Paragon_Ie\Halite\Asymmetric\Secret_Key
    {
        return $this->secret_key;
    }
}