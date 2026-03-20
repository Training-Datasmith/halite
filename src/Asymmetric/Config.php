<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Asymmetric;

use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\{Config as BaseConfig, Halite, Util};
use Paragon_Ie\Halite\Alerts\Invalid_Message;
/**
 * Class Config
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Config extends Base_Config
{
    /**
     * Get the configuration
     *
     *
     * @throws InvalidMessage
     */
    public static function get_config(string $header, string $mode = 'encrypt'): self
    {
        if (Binary::safe_strlen($header) < Halite::VERSION_TAG_LEN) {
            throw new Invalid_Message('Invalid version tag');
        }
        /*
         * We can safely omit the check on the first two bytes since
         * this is checked elsewhere. This is just a best-effort to
         * obtain the asymmetric configuration
         */
        $major = Util::chr_to_int($header[2]);
        $minor = Util::chr_to_int($header[3]);
        if ($mode === 'encrypt') {
            return new Config(self::get_config_encrypt($major, $minor));
        }
        throw new Invalid_Message('Invalid configuration mode: ' . $mode);
    }
    /**
     * Get the configuration for encrypt operations
     *
     * @throws InvalidMessage
     */
    public static function get_config_encrypt(int $major, int $minor): array
    {
        if ($major === 5) {
            switch ($minor) {
                case 0:
                    return ['ENCODING' => Halite::ENCODE_BASE64URLSAFE, 'HASH_DOMAIN_SEPARATION' => 'HaliteVersion5X25519SharedSecret', 'HASH_SCALARMULT' => true];
            }
        }
        if ($major === 4 || $major === 3) {
            switch ($minor) {
                case 0:
                    return ['ENCODING' => Halite::ENCODE_BASE64URLSAFE, 'HASH_DOMAIN_SEPARATION' => '', 'HASH_SCALARMULT' => false];
            }
        }
        throw new Invalid_Message('Invalid version tag');
    }
}