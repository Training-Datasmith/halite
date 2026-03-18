<?php

declare(strict_types=1);

use ParagonIE\Halite\HiddenString;
use ParagonIE\HiddenString\HiddenString as Outsourced;
use PHPUnit\Framework\TestCase;

/**
 * Class HiddenStringTest
 */
final class HiddenStringTest extends TestCase
{
    /**
     * @throws \Throwable
     */
    public function testConstructor()
    {
        $x = new HiddenString('test');
        $this->assertInstanceOf(Outsourced::class, $x);
    }
}
