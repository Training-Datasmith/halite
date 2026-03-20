<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Contract;

use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, File_Access_Denied};
/**
 * Interface StreamInterface
 *
 * A stream used by Halite, internally.
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Contract
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
interface Stream_Interface
{
    /**
     * Where are we in the buffer?
     */
    public function get_pos(): int;
    /**
     * How big is this buffer?
     */
    public function get_size(): int;
    /**
     * Get information about the stream.
     */
    public function get_stream_metadata(): array;
    /**
     * Read from a stream; prevent partial reads
     *
     * @throws FileAccessDenied
     * @throws CannotPerformOperation
     */
    public function read_bytes(int $num, bool $skip_tests = false): string;
    /**
     * How many bytes are left between here and the end of the stream?
     */
    public function remaining_bytes(): int;
    /**
     * Write to a stream; prevent partial writes
     *
     * @param ?int $num (number of bytes)
     * @throws FileAccessDenied
     */
    public function write_bytes(string $buf, ?int $num = null): int;
}