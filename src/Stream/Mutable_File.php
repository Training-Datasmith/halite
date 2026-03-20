<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Stream;

use function clearstatcache;
use function fclose;
use function file_exists;
use function fopen;
use function fread;
use function fseek;
use function fstat;
use function ftell;
use function fwrite;
use function in_array;
use function is_int;
use function is_readable;
use function is_resource;
use function is_string;
use function is_writable;
use function min;
use Paragon_Ie\Constant_Time\Binary;
use Paragon_Ie\Halite\Alerts\{Cannot_Perform_Operation, File_Access_Denied, Invalid_Type};
use Paragon_Ie\Halite\Contract\Stream_Interface;
use function stream_get_meta_data;
use function touch;
use TypeError;
/**
 * Class MutableFile
 *
 * Contrast with ReadOnlyFile: does not prevent race conditions by itself
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Stream
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
class Mutable_File implements Stream_Interface
{
    public const ALLOWED_MODES = ['r+b', 'w+b', 'cb', 'c+b', 'wb'];
    public const CHUNK = 8192;
    // PHP's fread() buffer is set to 8192 by default
    private bool $close_after = false;
    /**
     * @var resource
     */
    private $fp;
    private int $pos;
    private array|bool $stat = [];
    /**
     * MutableFile constructor.
     * @param string|resource $file
     *
     * @throws InvalidType
     * @throws FileAccessDenied
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function __construct($file)
    {
        if (is_string($file)) {
            if (!file_exists($file)) {
                if (!is_writable(dirname($file))) {
                    throw new File_Access_Denied('Could not write to directory that contains file');
                }
                touch($file);
                // Make the file exist
            }
            if (!is_readable($file)) {
                throw new File_Access_Denied('Could not open file for reading');
            }
            if (!is_writable($file)) {
                throw new File_Access_Denied('Could not open file for writing');
            }
            $fp = fopen($file, 'w+b');
            // @codeCoverageIgnoreStart
            if (!is_resource($fp)) {
                throw new File_Access_Denied('Could not open file for reading');
            }
            // @codeCoverageIgnoreEnd
            $this->fp = $fp;
            $this->close_after = true;
            $this->pos = 0;
            $this->stat = fstat($this->fp);
        } elseif (is_resource($file)) {
            /** @var array<string, string> $metadata */
            $metadata = stream_get_meta_data($file);
            if (!in_array($metadata['mode'], self::ALLOWED_MODES, true)) {
                throw new File_Access_Denied('Resource is in ' . $metadata['mode'] . ' mode, which is not allowed.');
            }
            $this->fp = $file;
            $this->pos = ftell($this->fp);
            $this->stat = fstat($this->fp);
        } else {
            throw new Invalid_Type('Argument 1: Expected a filename or resource');
        }
    }
    /**
     * Close the file handle.
     *
     *
     * @psalm-suppress InvalidPropertyAssignmentValue
     */
    public function close(): void
    {
        if ($this->close_after) {
            $this->close_after = false;
            fclose($this->fp);
            clearstatcache();
        }
    }
    /**
     * Make sure we invoke $this->close()
     */
    public function __destruct()
    {
        $this->close();
    }
    /**
     * Where are we in the buffer?
     */
    public function get_pos(): int
    {
        return ftell($this->fp);
    }
    /**
     * How big is this buffer?
     */
    public function get_size(): int
    {
        $stat = fstat($this->fp);
        return $stat['size'];
    }
    /**
     * Get information about the stream.
     */
    public function get_stream_metadata(): array
    {
        return stream_get_meta_data($this->fp);
    }
    /**
     * Read from a stream; prevent partial reads
     *
     *
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     */
    public function read_bytes(int $num, bool $skip_tests = false): string
    {
        // @codeCoverageIgnoreStart
        if ($num < 0) {
            throw new Cannot_Perform_Operation('num < 0');
        }
        // @codeCoverageIgnoreStart
        if ($num === 0) {
            return '';
        }
        if ($this->pos + $num > $this->stat['size']) {
            throw new Cannot_Perform_Operation('Out-of-bounds read');
        }
        // @codeCoverageIgnoreEnd
        $buf = '';
        $remaining = $num;
        do {
            if ($remaining <= 0) {
                // @codeCoverageIgnoreStart
                break;
                // @codeCoverageIgnoreEnd
            }
            $buf_size = min($remaining, self::CHUNK);
            $read = fread($this->fp, $buf_size);
            if (!is_string($read)) {
                // @codeCoverageIgnoreStart
                throw new File_Access_Denied('Could not read from the file');
                // @codeCoverageIgnoreEnd
            }
            $buf .= $read;
            $read_size = Binary::safe_strlen($read);
            $this->pos += $read_size;
            $remaining -= $read_size;
        } while ($remaining > 0);
        return $buf;
    }
    /**
     * Get number of bytes remaining
     */
    public function remaining_bytes(): int
    {
        /** @var array $stat */
        $stat = fstat($this->fp);
        /** @var int $pos */
        $pos = ftell($this->fp);
        return PHP_INT_MAX & (int) $stat['size'] - $pos;
    }
    /**
     * Set the current cursor position to the desired location
     *
     *
     *
     * @throws CannotPerformOperation
     * @codeCoverageIgnore
     */
    public function reset(int $position = 0): bool
    {
        $this->pos = $position;
        if (fseek($this->fp, $position, SEEK_SET) === 0) {
            return true;
        }
        throw new Cannot_Perform_Operation('fseek() failed');
    }
    /**
     * Write to a stream; prevent partial writes
     *
     * @param ?int $num (number of bytes)
     *
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws TypeError
     */
    public function write_bytes(string $buf, ?int $num = null): int
    {
        $buf_size = Binary::safe_strlen($buf);
        if (!is_int($num) || $num > $buf_size) {
            $num = $buf_size;
        }
        // @codeCoverageIgnoreStart
        if ($num < 0) {
            throw new Cannot_Perform_Operation('num < 0');
        }
        // @codeCoverageIgnoreEnd
        $remaining = $num;
        do {
            // @codeCoverageIgnoreStart
            if ($remaining <= 0) {
                break;
            }
            // @codeCoverageIgnoreEnd
            $written = fwrite($this->fp, $buf, $remaining);
            if ($written === false) {
                // @codeCoverageIgnoreStart
                throw new File_Access_Denied('Could not write to the file');
                // @codeCoverageIgnoreEnd
            }
            $buf = Binary::safe_substr($buf, $written, null);
            $this->pos += $written;
            $this->stat = fstat($this->fp);
            $remaining -= $written;
        } while ($remaining > 0);
        return $num;
    }
}