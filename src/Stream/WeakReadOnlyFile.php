<?php

declare (strict_types=1);
namespace Paragon_Ie\Halite\Stream;

/**
 * Class WeakReadOnlyFile
 *
 * Like ReadOnlyFile, but with weaker guarantees
 *
 * @package ParagonIE\Halite\Stream
 */
class Weak_Read_Only_File extends Read_Only_File
{
    public const ALLOWED_MODES = ['rb', 'r+b', 'wb', 'w+b', 'cb', 'c+b'];
}