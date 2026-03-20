<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Structure;

use function array_shift;
use function count;
use Paragon_Ie\Constant_Time\Hex;
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Digest_Length};
use Paragon_Ie\Halite\Util;
use const SODIUM_CRYPTO_GENERICHASH_BYTES;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MIN;
use Sodium_Exception;
use function sprintf;
use TypeError;
/**
 * Class MerkleTree
 *
 * An implementation of a Merkle hash tree, built on the BLAKE2b hash function
 * (provided by libsodium)
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
class Merkle_Tree
{
    public const MERKLE_LEAF = "\x01";
    public const MERKLE_BRANCH = "\x00";
    protected bool $root_calculated = false;
    protected string $root = '';
    /**
     * @var Node[]
     */
    protected array $nodes = [];
    protected string $personalization = '';
    protected int $output_size = SODIUM_CRYPTO_GENERICHASH_BYTES;
    /**
     * Instantiate a Merkle tree
     */
    public function __construct(Node ...$nodes)
    {
        $this->nodes = $nodes;
    }
    /**
     * Get the root hash of this Merkle tree.
     *
     * @param bool $raw - Do we want a raw string instead of a hex string?
     *
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     * @throws SodiumException
     */
    public function get_root(bool $raw = false): string
    {
        if (!$this->root_calculated) {
            $this->root = $this->calculate_root();
        }
        return $raw ? $this->root : Hex::encode($this->root);
    }
    /**
     * Merkle Trees are immutable. Return a replacement with extra nodes.
     *
     *
     *
     * @throws InvalidDigestLength
     */
    public function get_expanded_tree(Node ...$nodes): Merkle_Tree
    {
        $this_tree = $this->nodes;
        foreach ($nodes as $node) {
            $this_tree[] = $node;
        }
        return (new Merkle_Tree(...$this_tree))->set_hash_size($this->output_size)->set_personalization_string($this->personalization);
    }
    /**
     * Set the hash output size.
     *
     *
     *
     * @throws InvalidDigestLength
     */
    public function set_hash_size(int $size): self
    {
        if ($size < SODIUM_CRYPTO_GENERICHASH_BYTES_MIN) {
            throw new Invalid_Digest_Length(sprintf('Merkle roots must be at least %d long.', SODIUM_CRYPTO_GENERICHASH_BYTES_MIN));
        }
        if ($size > SODIUM_CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new Invalid_Digest_Length(sprintf('Merkle roots must be at most %d long.', SODIUM_CRYPTO_GENERICHASH_BYTES_MAX));
        }
        if ($this->output_size !== $size) {
            $this->root_calculated = false;
        }
        $this->output_size = $size;
        return $this;
    }
    /**
     * Sets the personalization string for the Merkle root calculation
     *
     *
     */
    public function set_personalization_string(string $str = ''): self
    {
        if ($this->personalization !== $str) {
            $this->root_calculated = false;
        }
        $this->personalization = $str;
        return $this;
    }
    /**
     * Explicitly recalculate the Merkle root
     *
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     * @throws SodiumException
     * @codeCoverageIgnore
     */
    public function trigger_root_calculation(): self
    {
        $this->root = $this->calculate_root();
        return $this;
    }
    /**
     * Calculate the Merkle root, taking care to distinguish between
     * leaves and branches (0x01 for the nodes, 0x00 for the branches)
     * to protect against second-preimage attacks
     *
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     * @throws SodiumException
     */
    protected function calculate_root(): string
    {
        $size = count($this->nodes);
        if ($size < 1) {
            return '';
        }
        $order = self::get_size_rounded_up($size);
        /** @var array<int, string> $hash */
        $hash = [];
        // Population (Use self::MERKLE_LEAF as a prefix)
        for ($i = 0; $i < $order; ++$i) {
            if ($i >= $size) {
                $hash[$i] = self::MERKLE_LEAF . $this->personalization . $this->nodes[$size - 1]->get_hash(true, $this->output_size, $this->personalization);
            } else {
                $hash[$i] = self::MERKLE_LEAF . $this->personalization . $this->nodes[$i]->get_hash(true, $this->output_size, $this->personalization);
            }
        }
        // Calculation (Use self::MERKLE_BRANCH as a prefix)
        do {
            /** @var array<int, string> $tmp */
            $tmp = [];
            $j = 0;
            for ($i = 0; $i < $order; $i += 2) {
                $curr = (string) ($hash[$i] ?? '');
                if (empty($hash[$i + 1])) {
                    // @codeCoverageIgnoreStart
                    $tmp[$j] = Util::raw_hash(self::MERKLE_BRANCH . $this->personalization . $curr . $curr, $this->output_size);
                    // @codeCoverageIgnoreEnd
                } else {
                    $curr = $hash[$i] ?? '';
                    $next = $hash[$i + 1] ?? '';
                    $tmp[$j] = Util::raw_hash(self::MERKLE_BRANCH . $this->personalization . $curr . $next, $this->output_size);
                }
                ++$j;
            }
            $hash = $tmp;
            $order >>= 1;
        } while ($order > 1);
        // We should only have one value left:
        $this->root_calculated = true;
        return (string) array_shift($hash);
    }
    /**
     * Let's go ahead and round up to the nearest multiple of 2
     *
     *
     */
    public static function get_size_rounded_up(int $input_size): int
    {
        $order = 1;
        while ($order < $input_size) {
            $order <<= 1;
        }
        return $order;
    }
}