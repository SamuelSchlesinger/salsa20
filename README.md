# Salsa20

A Rust implementation of the Salsa20 stream cipher algorithm.

## Overview

Salsa20 is a stream cipher designed by Daniel J. Bernstein in 2005. This crate provides a Rust implementation of the Salsa20 algorithm, following the original specification. The implementation includes support for both 16-byte (128-bit) and 32-byte (256-bit) keys.

## Features

- Pure Rust implementation of the Salsa20 algorithm
- Support for 128-bit and 256-bit keys
- Simple API for encryption and decryption
- Comprehensive test suite with test vectors from the Salsa20 specification
- PRNG implementation that implements the `rand_core` traits

## Usage

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
salsa20 = "0.1.0"
```

### Basic Example

```rust
use salsa20::{salsa20_encrypt, salsa20_decrypt};

// Key parts for 256-bit key
let k0 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
let k1 = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];

// Message to encrypt
let message = b"This is a secret message";

// Encrypt
let ciphertext = salsa20_encrypt(message, k0, k1);

// Decrypt
let decrypted = salsa20_decrypt(&ciphertext, k0, k1);
assert_eq!(&decrypted, message);
```

### Using 128-bit Keys

For 128-bit keys, use the `salsa20_encrypt_k16` and `salsa20_decrypt_k16` functions:

```rust
use salsa20::{salsa20_encrypt_k16, salsa20_decrypt_k16};

// 128-bit key
let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

// Message to encrypt
let message = b"This is a secret message";

// Encrypt
let ciphertext = salsa20_encrypt_k16(message, key);

// Decrypt
let decrypted = salsa20_decrypt_k16(&ciphertext, key);
assert_eq!(&decrypted, message);
```

### Using the RNG

The crate also provides a pseudorandom number generator based on Salsa20:

```rust
use salsa20::Salsa20Rng;
use rand_core::{RngCore, SeedableRng};

// Create a seeded RNG
let seed = [0u8; 32]; // Use a cryptographically secure seed in real applications
let mut rng = Salsa20Rng::from_seed(seed);

// Generate random values
let random_u32 = rng.next_u32();
let random_u64 = rng.next_u64();

// Fill a buffer with random bytes
let mut buffer = [0u8; 10];
rng.fill_bytes(&mut buffer);
```

## Security Considerations

- For cryptographic security, use a secure random number generator to generate keys
- This implementation does not handle nonce management - in a real application, you should ensure nonces are never reused with the same key
- For production use, consider using a mature, audited cryptographic library

## License

This crate is available under the MIT License.

## References

- [Salsa20 specification](https://cr.yp.to/snuffle/spec.pdf)
- [eSTREAM portfolio](https://www.ecrypt.eu.org/stream/salsa20pf.html)
