<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Structure;

use function count;
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, Invalid_Digest_Length};
use Paragon_Ie\Halite\Util;
use Sodium_Exception;
use TypeError;
/**
 * Class TrimmedMerkleTree
 *
 * A variant of a Merkle tree that silently passes the dangling nodes up
 * instead of duplicating and then hashing.
 *
 * If you're planning to implement this into some sort of crypto-currency,
 * you'll almost certainly want to use the Trimmed variant.
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
class Trimmed_Merkle_Tree extends Merkle_Tree
{
    /**
     * Calculate the Merkle root, taking care to distinguish between
     * leaves and branches (0x01 for the nodes, 0x00 for the branches)
     * to protect against second-preimage attacks
     *
     *
     * @throws CannotPerformOperation
     * @throws SodiumException
     * @throws TypeError
     * @psalm-suppress EmptyArrayAccess Psalm is misreading array elements
     */
    protected function calculate_root(): string
    {
        $size = count($this->nodes);
        if ($size < 1) {
            return '';
        }
        /** @var array<int, string> $hash */
        $hash = [];
        // Population (Use self::MERKLE_LEAF as a prefix)
        for ($i = 0; $i < $size; ++$i) {
            $hash[$i] = self::MERKLE_LEAF . $this->personalization . $this->nodes[$i]->get_hash(true, $this->output_size, $this->personalization);
        }
        // Calculation (Use self::MERKLE_BRANCH as a prefix)
        do {
            /** @var array<int, string> $tmp */
            $tmp = [];
            $j = 0;
            for ($i = 0; $i < $size; $i += 2) {
                if (empty($hash[$i + 1])) {
                    $tmp[$j] = $hash[$i];
                } elseif (!empty($hash[$i])) {
                    $tmp[$j] = Util::raw_hash(self::MERKLE_BRANCH . $this->personalization . $hash[$i] . $hash[$i + 1], $this->output_size);
                }
                ++$j;
            }
            $hash = $tmp;
            $size >>= 1;
        } while ($size > 1);
        // We should only have one value left:
        $this->root_calculated = true;
        return (string) array_shift($hash);
    }
    /**
     * Merkle Trees are immutable. Return a replacement with extra nodes.
     *
     *
     *
     * @throws InvalidDigestLength
     */
    public function get_expanded_tree(Node ...$nodes): Trimmed_Merkle_Tree
    {
        $this_tree = $this->nodes;
        foreach ($nodes as $node) {
            $this_tree[] = $node;
        }
        $new = new Trimmed_Merkle_Tree(...$this_tree);
        $new->set_hash_size($this->output_size);
        $new->set_personalization_string($this->personalization);
        return $new;
    }
}