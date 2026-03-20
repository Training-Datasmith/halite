<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use Paragon_Ie\Halite\Alerts\{Cannot_Clone_Key, Cannot_Serialize_Key};
use Paragon_Ie\Hidden_String\Hidden_String;
use TypeError;
/**
 * Class Key
 *
 * Base class for all cryptography secrets
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
class Key implements \Stringable
{
    protected bool $is_public_key = false;
    protected bool $is_signing_key = false;
    protected bool $is_asymmetric_key = false;
    private string $key_material = '';
    /**
     * Don't let this ever succeed
     *
     * @throws CannotCloneKey
     * @codeCoverageIgnore
     */
    public function __clone()
    {
        throw new Cannot_Clone_Key();
    }
    /**
     * You probably should not be using this directly.
     *
     * @param HiddenString $keyMaterial - The actual key data
     * @throws \TypeError
     */
    public function __construct(Hidden_String $key_material)
    {
        $this->key_material = Util::safe_strcpy($key_material->get_string());
    }
    /**
     * Hide this from var_dump(), etc.
     *
     * @return array
     * @codeCoverageIgnore
     */
    public function __debugInfo()
    {
        // We exclude $this->keyMaterial
        return ['isAsymmetricKey' => $this->is_asymmetric_key, 'isPublicKey' => $this->is_public_key, 'isSigningKey' => $this->is_signing_key];
    }
    /**
     * Make sure you wipe the key from memory on destruction
     */
    public function __destruct()
    {
        if (!$this->is_public_key) {
            Util::memzero($this->key_material);
            $this->key_material = '';
        }
    }
    /**
     * Don't allow this object to ever be serialized
     * @throws CannotSerializeKey
     * @codeCoverageIgnore
     */
    public function __sleep()
    {
        throw new Cannot_Serialize_Key();
    }
    /**
     * Don't allow this object to ever be unserialized
     * @throws CannotSerializeKey
     * @codeCoverageIgnore
     */
    public function __wakeup()
    {
        throw new Cannot_Serialize_Key();
    }
    /**
     * Get public keys
     *
     * @codeCoverageIgnore
     */
    public function __toString(): string
    {
        if ($this->is_public_key) {
            return $this->key_material;
        }
        return '';
    }
    /**
     * Get the actual key material
     *
     * @throws TypeError
     */
    public function get_raw_key_material(): string
    {
        return Util::safe_strcpy($this->key_material);
    }
    /**
     * Is this a part of a key pair?
     */
    public function is_asymmetric_key(): bool
    {
        return $this->is_asymmetric_key;
    }
    /**
     * Is this a signing key?
     */
    public function is_encryption_key(): bool
    {
        return !$this->is_signing_key;
    }
    /**
     * Is this a public key?
     */
    public function is_public_key(): bool
    {
        return $this->is_public_key;
    }
    /**
     * Is this a secret key?
     */
    public function is_secret_key(): bool
    {
        return !$this->is_public_key;
    }
    /**
     * Is this a signing key?
     */
    public function is_signing_key(): bool
    {
        return $this->is_signing_key;
    }
}