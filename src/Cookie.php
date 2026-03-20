<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite;

use function hash_equals;
use function is_string;
use function json_decode;
use function json_encode;
use function preg_match;
use Paragon_Ie\Constant_Time\{Base64url_Safe, Binary, Hex};
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Digest_Length, Invalid_Message, Invalid_Signature, Invalid_Type};
use Paragon_Ie\Halite\Symmetric\{Config as SymmetricConfig, Crypto, Encryption_Key};
use Paragon_Ie\Hidden_String\Hidden_String;
use function setcookie;
use Sodium_Exception;
use TypeError;
/**
 * Class Cookie
 *
 * Secure encrypted cookies
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
 *
 * @codeCoverageIgnore
 */
final class Cookie
{
    /**
     * Cookie constructor.
     */
    public function __construct(protected Encryption_Key $key)
    {
    }
    /**
     * Hide this from var_dump(), etc.
     */
    public function __debugInfo(): array
    {
        return ['key' => 'private'];
    }
    /**
     * Fetch a value from an encrypted cookie
     *
     *
     * @return mixed|null (typically an array)
     *
     * @throws InvalidDigestLength
     * @throws InvalidSignature
     * @throws CannotPerformOperation
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public function fetch(
        #[\Sensitive_Parameter]
        string $name
    )
    {
        if (!isset($_COOKIE[$name])) {
            return null;
        }
        try {
            /** @var string|array|int|float|bool $stored */
            $stored = $_COOKIE[$name];
            if (!is_string($stored)) {
                throw new Invalid_Type('Cookie value is not a string');
            }
            $config = self::get_config($stored);
            $encoding = $config->ENCODING;
            $decrypted = Crypto::decrypt($stored, $this->key, $encoding);
            return json_decode($decrypted->get_string(), true);
        } catch (Invalid_Message) {
            return null;
        }
    }
    /**
     * Get the configuration for this version of halite
     *
     * @param string $stored   A stored password hash
     *
     * @throws InvalidMessage
     * @throws TypeError
     */
    protected static function get_config(string $stored): Symmetric_Config
    {
        $length = Binary::safe_strlen($stored);
        // This doesn't even have a header.
        if ($length < 8) {
            throw new Invalid_Message('Encrypted password hash is way too short.');
        }
        if (hash_equals(Binary::safe_substr($stored, 0, 5), Halite::VERSION_PREFIX)) {
            $decoded = Base64url_Safe::decode($stored);
            return Symmetric_Config::get_config($decoded, 'encrypt');
        }
        $v = Hex::decode(Binary::safe_substr($stored, 0, 8));
        return Symmetric_Config::get_config($v, 'encrypt');
    }
    /**
     * Store a value in an encrypted cookie
     *
     * @param mixed $value
     * @param int $expire    (defaults to 0)
     * @param string $path   (defaults to '/')
     * @param string $domain (defaults to NULL)
     * @param bool $secure   (defaults to TRUE)
     * @param bool $httpOnly (defaults to TRUE)
     * @param string $sameSite (defaults to 'Lax'; PHP >= 7.3.0)
     *
     *
     * @throws InvalidDigestLength
     * @throws CannotPerformOperation
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \InvalidArgumentException
     * @throws SodiumException
     * @throws TypeError
     * @psalm-suppress InvalidArgument  PHP version incompatibilities
     * @psalm-suppress MixedArgument
     */
    public function store(
        #[\Sensitive_Parameter]
        string $name,
        #[\Sensitive_Parameter]
        $value,
        int $expire = 0,
        string $path = '/',
        string $domain = '',
        bool $secure = true,
        bool $http_only = true,
        string $same_site = 'Lax'
    ): bool
    {
        // RFC 6265: cookie names must not contain separators or control characters
        if (preg_match('/[\x00-\x1f\x7f()<>@,;:\\\\\\"\/\[\]?={} \t]/', $name)) {
            throw new \InvalidArgumentException('Invalid cookie name: contains characters forbidden by RFC 6265.');
        }
        $val = Crypto::encrypt(new Hidden_String((string) json_encode($value)), $this->key);
        $options = ['expires' => $expire, 'path' => $path, 'domain' => $domain, 'secure' => $secure, 'httponly' => $http_only, 'samesite' => $same_site];
        return setcookie($name, $val, $options);
    }
}