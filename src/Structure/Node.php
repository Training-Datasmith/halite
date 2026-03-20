<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Structure;

use Paragon_Ie\Halite\Alerts\Cannot_Perform_Operation;
use Paragon_Ie\Halite\Util;
use const SODIUM_CRYPTO_GENERICHASH_BYTES;
use Sodium_Exception;
use TypeError;
/**
 * Class Node
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Structure
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
class Node
{
    /**
     * Node constructor.
     */
    public function __construct(private readonly string $data)
    {
    }
    /**
     * Get the data
     */
    public function get_data(): string
    {
        return $this->data;
    }
    /**
     * Get a hash of the data (defaults to hex encoded)
     *
     * @param bool $raw
     *
     * These two aren't really meant to be used externally:
     *
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     * @throws SodiumException
     */
    public function get_hash(bool $raw = false, int $output_size = SODIUM_CRYPTO_GENERICHASH_BYTES, string $personalization = ''): string
    {
        if ($raw) {
            return Util::raw_hash($personalization . $this->data, $output_size);
        }
        return Util::hash($personalization . $this->data, $output_size);
    }
    /**
     * Nodes are immutable, but you can create one with extra data.
     *
     *
     */
    public function get_expanded_node(string $concat): Node
    {
        return new Node($this->data . $concat);
    }
}