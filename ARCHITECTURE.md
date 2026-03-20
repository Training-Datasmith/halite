# Architecture: halite

## Purpose
Halite — a high-level cryptography library built on libsodium. Provides easy-to-use symmetric encryption, asymmetric encryption, digital signatures, password hashing, file encryption, and authenticated cookies — all using modern, safe algorithms with no configuration footguns.

## Directory Structure
```
src/
  Halite.php                    # Version constants and sodium extension check
  Key.php / Key_Pair.php        # Abstract key and key-pair base types
  Key_Factory.php               # Generates, derives, exports, and imports all key types
  Symmetric/
    Encryption_Key.php          # Key for symmetric authenticated encryption (XSalsa20-Poly1305)
    Authentication_Key.php      # Key for symmetric MAC (BLAKE2b or HMAC)
    Crypto.php                  # encrypt(), decrypt(), authenticate(), verify()
    Config.php                  # Algorithm configuration per Halite version
  Asymmetric/
    Encryption_Public_Key.php / Encryption_Secret_Key.php  # X25519 key pair
    Signature_Public_Key.php / Signature_Secret_Key.php    # Ed25519 key pair
    Crypto.php                  # encrypt(), decrypt(), sign(), verify(), seal(), unseal()
    Config.php
  Password.php                  # Password hashing (Argon2id) and verification
  Cookie.php                    # Authenticated encrypted cookie helpers
  File.php                      # Streaming file encryption / decryption / signing
  Hidden_String.php             # Sensitive string wrapper (zeroed on destruct)
  Encryption_Key_Pair.php / Signature_Key_Pair.php
  Stream/
    Read_Only_File.php / Mutable_File.php / Weak_Read_Only_File.php
  Structure/
    Merkle_Tree.php / Node.php / Trimmed_Merkle_Tree.php  # Merkle tree for integrity verification
  Alerts/                       # Typed exception hierarchy for all error conditions
  Contract/Stream_Interface.php
  Util.php                      # Secure comparison, hex encode/decode helpers
```

## Key Design Decisions
- **Opinionated algorithm selection** — Halite hard-codes modern, safe algorithms (X25519 for key exchange, Ed25519 for signatures, XSalsa20-Poly1305 for encryption, Argon2id for passwords). No algorithm negotiation; no risk of choosing a weak cipher.
- **Versioned encoding** — encrypted messages and key exports include a version header, enabling forward-compatible algorithm upgrades without breaking existing ciphertexts.
- **Hidden_String** — sensitive strings (passwords, passphrases) are wrapped in `Hidden_String` which zeroes the memory on destruction, reducing plaintext exposure window.
- **Key factories** — all key generation and derivation goes through `Key_Factory`, ensuring keys are always created with sufficient entropy and cannot be accidentally constructed from arbitrary data.
- **Streaming file encryption** — `File` uses the libsodium streaming API, processing large files in chunks without loading them fully into memory.

## Extension Points
- Implement `Stream_Interface` to add custom input/output sources for file encryption.
- Use `Key_Factory::export()` / `import()` to persist and restore keys securely.
- Use `Structure\Merkle_Tree` for audit-log integrity verification independent of the encryption layer.

## Dependency Flow
```
Key_Factory::generateEncryptionKey() → Symmetric\Encryption_Key
  └─ Symmetric\Crypto::encrypt($plaintext, $key) → encoded ciphertext string
       └─ libsodium: crypto_secretbox()

Key_Factory::generateSignatureKeyPair() → Signature_Key_Pair
  └─ Asymmetric\Crypto::sign($message, $secretKey) → signature
  └─ Asymmetric\Crypto::verify($message, $publicKey, $signature) → bool

Password::hash($password) → Argon2id hash string
Password::verify($password, $hash) → bool
```
