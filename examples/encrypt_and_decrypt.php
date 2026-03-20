<?php

declare(strict_types=1);

/**
 * Example: symmetric encryption and password hashing with Halite.
 *
 * Run from the halite project root:
 *   php examples/encrypt_and_decrypt.php
 */

require __DIR__ . '/../vendor/autoload.php';

use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as SymmetricCrypto;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Password;

// --- Symmetric encryption ---
$key = KeyFactory::generateEncryptionKey();

$plaintext = new HiddenString('Super secret message');
$ciphertext = SymmetricCrypto::encrypt($plaintext, $key);

echo "Ciphertext: " . substr($ciphertext, 0, 40) . "...\n";

$decrypted = SymmetricCrypto::decrypt($ciphertext, $key);
echo "Decrypted: " . $decrypted->getString() . "\n";

echo "\n";

// --- Password hashing ---
$password = new HiddenString('correcthorsebatterystaple');
$hash = Password::hash($password);

echo "Hash: " . substr($hash->getString(), 0, 30) . "...\n";

$valid = Password::verify($password, $hash, $key);
echo "Password valid: " . ($valid ? 'yes' : 'no') . "\n";

// --- Key export / import ---
$keyMaterial = KeyFactory::export($key);
echo "Exported key (hex): " . substr($keyMaterial->getString(), 0, 20) . "...\n";
