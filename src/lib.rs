//! # Salsa20
//! 
//! A Rust implementation of the Salsa20 stream cipher algorithm.
//! 
//! Salsa20 is a stream cipher designed by Daniel J. Bernstein. This crate provides
//! an implementation of the algorithm following the original specification.
//! 
//! ## Features
//! 
//! - Support for both 16-byte (128-bit) and 32-byte (256-bit) keys
//! - Simple API for encryption and decryption
//! - Pure Rust implementation
//! 
//! ## Example
//! 
//! ```
//! use salsa20::{salsa20_encrypt, salsa20_decrypt};
//! 
//! // Create a test message
//! let message = b"This is a test message for Salsa20 encryption";
//! 
//! // Create key halves for a 256-bit key
//! let k0 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
//! let k1 = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
//! 
//! // Encrypt the message
//! let ciphertext = salsa20_encrypt(message, k0, k1);
//! 
//! // Decrypt the ciphertext
//! let decrypted = salsa20_decrypt(&ciphertext, k0, k1);
//! 
//! // Verify that decryption recovers the original message
//! assert_eq!(decrypted, message);
//! ```
//! 
//! For 128-bit keys, use the `salsa20_encrypt_k16` and `salsa20_decrypt_k16` functions.

/// A 32-bit word used throughout the Salsa20 algorithm.
type Word = u32;

/// A quarter block consisting of 4 words used in the quarterround operation.
type Quarter = [u32; 4];

/// Performs the Salsa20 quarterround function on a 4-word state.
///
/// The quarterround function is the basic transformation in the Salsa20 encryption
/// algorithm. It adds, XORs, and rotates words to create nonlinearity.
///
/// # Arguments
///
/// * `y` - An array of 4 words representing the input state
///
/// # Returns
///
/// * A new array of 4 words representing the transformed state
fn quarterround(y: Quarter) -> Quarter {
    let z1 = y[1] ^ y[0].wrapping_add(y[3]).rotate_left(7);
    let z2 = y[2] ^ z1.wrapping_add(y[0]).rotate_left(9);
    let z3 = y[3] ^ z2.wrapping_add(z1).rotate_left(13);
    let z0 = y[0] ^ z3.wrapping_add(z2).rotate_left(18);
    [z0, z1, z2, z3]
}

/// Tests the quarterround function against test vectors from the Salsa20 specification
#[test]
fn test_quarterround() {
    // Test vector 1: All zeros
    assert_eq!(
        quarterround([0x00000000, 0x00000000, 0x00000000, 0x00000000]),
        [0x00000000, 0x00000000, 0x00000000, 0x00000000]
    );
    
    // Test vector 2: Only first word is non-zero
    assert_eq!(
        quarterround([0x00000001, 0x00000000, 0x00000000, 0x00000000]),
        [0x08008145, 0x00000080, 0x00010200, 0x20500000]
    );
    
    // Test vector 3: Only second word is non-zero
    assert_eq!(
        quarterround([0x00000000, 0x00000001, 0x00000000, 0x00000000]),
        [0x88000100, 0x00000001, 0x00000200, 0x00402000]
    );
    
    // Test vector 4: Only third word is non-zero
    assert_eq!(
        quarterround([0x00000000, 0x00000000, 0x00000001, 0x00000000]),
        [0x80040000, 0x00000000, 0x00000001, 0x00002000]
    );
    
    // Test vector 5: Only fourth word is non-zero
    assert_eq!(
        quarterround([0x00000000, 0x00000000, 0x00000000, 0x00000001]),
        [0x00048044, 0x00000080, 0x00010000, 0x20100001]
    );
    
    // Test vector 6: Complex input
    assert_eq!(
        quarterround([0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137]),
        [0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3]
    );
    
    // Test vector 7: Different complex input
    assert_eq!(
        quarterround([0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b]),
        [0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c]
    );
}

/// A complete 16-word row state for the Salsa20 algorithm.
type Row = [u32; 16];

/// Performs the Salsa20 rowround function on a 16-word state.
///
/// The rowround function applies the quarterround function to 4 separate groups of 4 words,
/// where each group is a "row" in the 4x4 matrix representation of the state.
///
/// # Arguments
///
/// * `y` - An array of 16 words representing the input state
///
/// # Returns
///
/// * A new array of 16 words representing the transformed state
fn rowround(y: Row) -> Row {
    let [z0, z1, z2, z3] = quarterround([y[0], y[1], y[2], y[3]]);
    let [z5, z6, z7, z4] = quarterround([y[5], y[6], y[7], y[4]]);
    let [z10, z11, z8, z9] = quarterround([y[10], y[11], y[8], y[9]]);
    let [z15, z12, z13, z14] = quarterround([y[15], y[12], y[13], y[14]]);
    [
        z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15,
    ]
}

#[test]
fn test_rowround() {
    assert_eq!(
        rowround([
            0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
            0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
            0x00000000, 0x00000000
        ]),
        [
            0x08008145, 0x00000080, 0x00010200, 0x20500000, 0x20100001, 0x00048044, 0x00000080,
            0x00010000, 0x00000001, 0x00002000, 0x80040000, 0x00000000, 0x00000001, 0x00000200,
            0x00402000, 0x88000100
        ]
    );
    assert_eq!(
        rowround([
            0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365, 0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3,
            0xda0a64f6, 0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e, 0xe859c100, 0xea4d84b7,
            0x0f619bff, 0xbc6e965a
        ]),
        [
            0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86, 0x949d2192, 0x764b7754, 0xe408d9b9,
            0x7a41b4d1, 0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8, 0x0040ede5, 0xb545fbce,
            0xd257ed4f, 0x1818882d
        ]
    );
}

/// A complete 16-word column state for the Salsa20 algorithm.
/// This is the same as Row but represents a different conceptual view of the state.
type Column = [u32; 16];

/// Performs the Salsa20 columnround function on a 16-word state.
///
/// The columnround function applies the quarterround function to 4 separate groups of 4 words,
/// where each group is a "column" in the 4x4 matrix representation of the state.
///
/// # Arguments
///
/// * `x` - An array of 16 words representing the input state
///
/// # Returns
///
/// * A new array of 16 words representing the transformed state
fn columnround(x: Column) -> Column {
    let [y0, y4, y8, y12] = quarterround([x[0], x[4], x[8], x[12]]);
    let [y5, y9, y13, y1] = quarterround([x[5], x[9], x[13], x[1]]);
    let [y10, y14, y2, y6] = quarterround([x[10], x[14], x[2], x[6]]);
    let [y15, y3, y7, y11] = quarterround([x[15], x[3], x[7], x[11]]);
    [
        y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15,
    ]
}

#[test]
fn test_columnround() {
    assert_eq!(
        columnround([
            0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
            0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
            0x00000000, 0x00000000
        ]),
        [
            0x10090288, 0x00000000, 0x00000000, 0x00000000, 0x00000101, 0x00000000, 0x00000000,
            0x00000000, 0x00020401, 0x00000000, 0x00000000, 0x00000000, 0x40a04001, 0x00000000,
            0x00000000, 0x00000000
        ]
    );
    assert_eq!(
        columnround([
            0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365, 0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3,
            0xda0a64f6, 0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e, 0xe859c100, 0xea4d84b7,
            0x0f619bff, 0xbc6e965a
        ]),
        [
            0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a, 0x90a20123, 0xead3c4f3, 0x63a091a0,
            0xf0708d69, 0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c, 0x481c2027, 0x53a8e4b5,
            0x4c1f89c5, 0x3f78c9c8
        ]
    );
}

/// Performs a complete Salsa20 doubleround by applying a columnround followed by a rowround.
///
/// The doubleround is the core function in the Salsa20 hash function, applying both column
/// and row transformations to thoroughly mix the state.
///
/// # Arguments
///
/// * `x` - An array of 16 words representing the input state
///
/// # Returns
///
/// * A new array of 16 words representing the transformed state
fn doubleround(x: Column) -> Row {
    rowround(columnround(x))
}

#[test]
fn test_doubleround() {
    assert_eq!(
        doubleround([
            0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000
        ]),
        [
            0x8186a22d, 0x0040a284, 0x82479210, 0x06929051, 0x08000090, 0x02402200, 0x00004000,
            0x00800000, 0x00010200, 0x20400000, 0x08008104, 0x00000000, 0x20500000, 0xa0000040,
            0x0008180a, 0x612a8020
        ]
    );
    assert_eq!(
        doubleround([
            0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57, 0xb75540d3, 0x43e93a4c, 0x3a6f2aa0,
            0x726d6b36, 0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11, 0x054bf545, 0x254dd653,
            0xd9421b6d, 0x67b276c1
        ]),
        [
            0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0, 0x50440492, 0xf07cad19, 0xae344aa0,
            0xdf4cfdfc, 0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00, 0xa74b2ad6, 0xbc331c5c,
            0x1dda24c7, 0xee928277
        ]
    );
}

/// Tests little-endian byte order conversion which is crucial for Salsa20
#[test]
fn test_littleendian() {
    assert_eq!(u32::from_le_bytes([0, 0, 0, 0]), 0x00000000);
    assert_eq!(u32::from_le_bytes([86, 75, 30, 9]), 0x091e4b56);
    assert_eq!(u32::from_le_bytes([255, 255, 255, 250]), 0xfaffffff);
}

/// Implements the core Salsa20 hash function.
///
/// The Salsa20 function takes a 64-byte input and produces a 64-byte output
/// by interpreting the input as sixteen 32-bit words in little-endian format,
/// applying 10 doubleround transformations, and adding the result to the original input.
///
/// # Arguments
///
/// * `x` - A 64-byte array representing the input
///
/// # Returns
///
/// * A 64-byte array representing the output
fn salsa20(x: [u8; 64]) -> [u8; 64] {
    // Convert input bytes to 16 little-endian 32-bit words
    let mut x = [
        u32::from_le_bytes([x[0], x[1], x[2], x[3]]),
        u32::from_le_bytes([x[4], x[5], x[6], x[7]]),
        u32::from_le_bytes([x[8], x[9], x[10], x[11]]),
        u32::from_le_bytes([x[12], x[13], x[14], x[15]]),
        u32::from_le_bytes([x[16], x[17], x[18], x[19]]),
        u32::from_le_bytes([x[20], x[21], x[22], x[23]]),
        u32::from_le_bytes([x[24], x[25], x[26], x[27]]),
        u32::from_le_bytes([x[28], x[29], x[30], x[31]]),
        u32::from_le_bytes([x[32], x[33], x[34], x[35]]),
        u32::from_le_bytes([x[36], x[37], x[38], x[39]]),
        u32::from_le_bytes([x[40], x[41], x[42], x[43]]),
        u32::from_le_bytes([x[44], x[45], x[46], x[47]]),
        u32::from_le_bytes([x[48], x[49], x[50], x[51]]),
        u32::from_le_bytes([x[52], x[53], x[54], x[55]]),
        u32::from_le_bytes([x[56], x[57], x[58], x[59]]),
        u32::from_le_bytes([x[60], x[61], x[62], x[63]]),
    ];

    // Initialize result with input
    let mut z = x;

    // Apply 10 doublerounds
    for _i in 0..10 {
        z = doubleround(z);
    }

    // Prepare final result by adding the transformed state to the original
    let mut y: [u8; 64] = [0u8; 64];

    // Convert result back to bytes and add to original input
    for i in 0..16 {
        y[i * 4..(i + 1) * 4].copy_from_slice(&u32::to_le_bytes(z[i].wrapping_add(x[i])));
    }

    y
}

/// Tests the core Salsa20 hash function against known test vectors
#[test]
fn test_salsa20() {
    // Test vector 1: All zeros input
    assert_eq!(
        salsa20([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ]),
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ]
    );
    
    // Test vector 2: Standard test input - from the Salsa20 specification
    assert_eq!(
        salsa20([
            211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136, 49, 237, 179,
            48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207, 31, 240, 32, 63, 15, 83, 93,
            161, 116, 147, 48, 113, 238, 55, 204, 36, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26,
            244, 243, 88, 118, 104, 54
        ]),
        [
            109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154, 29, 29,
            150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57, 118, 40, 152, 157, 180,
            57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114, 219, 236, 232, 135, 111, 155, 110, 18,
            24, 232, 95, 158, 179, 19, 48, 202
        ]
    );
    
    // Test vector 3: Another standard test input from the specification
    assert_eq!(
        salsa20([
            88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 191, 187, 234,
            136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 86, 16, 179, 207, 49, 237,
            179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 238, 55, 204, 36, 31, 240, 32, 63, 15,
            83, 93, 161, 116, 147, 48, 113
        ]),
        [
            179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 26, 110,
            170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 69, 144, 51, 57,
            29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 27, 111, 114, 114, 118, 40, 152,
            157, 180, 57, 27, 94, 107, 42, 236, 35
        ]
    );
}

/// Generates a Salsa20 keystream block using a 32-byte key.
///
/// This function prepares a 64-byte input block for the Salsa20 hash function
/// using a 32-byte key split into two 16-byte parts and a 16-byte nonce.
/// The block follows the structure specified in the Salsa20 specification.
///
/// # Arguments
///
/// * `k0` - The first 16 bytes of the key
/// * `k1` - The second 16 bytes of the key
/// * `n` - A 16-byte nonce (can include counter values)
///
/// # Returns
///
/// * A 64-byte array containing the generated keystream block
fn salsa20k32(k0: [u8; 16], k1: [u8; 16], n: [u8; 16]) -> [u8; 64] {
    // "expand 32-byte k" in ascii - this is the standard constant for 32-byte keys
    let sigma_0 = [101u8, 120, 112, 97]; // "expa"
    let sigma_1 = [110u8, 100, 32, 51];  // "nd 3"
    let sigma_2 = [50u8, 45, 98, 121];   // "2-by"
    let sigma_3 = [116u8, 101, 32, 107]; // "te k"

    // Prepare the input block with constants, key parts, and nonce
    let mut bytes = [0u8; 64];
    bytes[0..4].copy_from_slice(&sigma_0);    // Constant 0
    bytes[4..20].copy_from_slice(&k0);        // Key part 0
    bytes[20..24].copy_from_slice(&sigma_1);  // Constant 1
    bytes[24..40].copy_from_slice(&n);        // Nonce
    bytes[40..44].copy_from_slice(&sigma_2);  // Constant 2
    bytes[44..60].copy_from_slice(&k1);       // Key part 1
    bytes[60..64].copy_from_slice(&sigma_3);  // Constant 3

    // Apply the Salsa20 hash function to generate the keystream
    salsa20(bytes)
}

/// Generates a Salsa20 keystream block using a 16-byte key.
///
/// This function prepares a 64-byte input block for the Salsa20 hash function
/// using a 16-byte key (used twice) and a 16-byte nonce.
/// The block follows the structure specified in the Salsa20 specification for 16-byte keys.
///
/// # Arguments
///
/// * `k` - The 16-byte key
/// * `n` - A 16-byte nonce (can include counter values)
///
/// # Returns
///
/// * A 64-byte array containing the generated keystream block
fn salsa20k16(k: [u8; 16], n: [u8; 16]) -> [u8; 64] {
    // "expand 16-byte k" in ascii - this is the standard constant for 16-byte keys
    let tau_0 = [101u8, 120, 112, 97]; // "expa"
    let tau_1 = [110u8, 100, 32, 49];  // "nd 1"
    let tau_2 = [54u8, 45, 98, 121];   // "6-by"
    let tau_3 = [116u8, 101, 32, 107]; // "te k"

    // Prepare the input block with constants, key (repeated), and nonce
    let mut bytes = [0u8; 64];
    bytes[0..4].copy_from_slice(&tau_0);   // Constant 0
    bytes[4..20].copy_from_slice(&k);      // Key (first instance)
    bytes[20..24].copy_from_slice(&tau_1); // Constant 1
    bytes[24..40].copy_from_slice(&n);     // Nonce
    bytes[40..44].copy_from_slice(&tau_2); // Constant 2
    bytes[44..60].copy_from_slice(&k);     // Key (repeated)
    bytes[60..64].copy_from_slice(&tau_3); // Constant 3

    // Apply the Salsa20 hash function to generate the keystream
    salsa20(bytes)
}

/// Tests the key expansion functions for both 16-byte and 32-byte keys
#[test]
fn test_salsa20k() {
    // Create test keys and nonce
    let mut k0: [u8; 16] = [0u8; 16];
    for i in 0u8..16 {
        k0[i as usize] = i + 1;  // Key values 1-16
    }
    
    let mut k1: [u8; 16] = [0u8; 16];
    for i in 0u8..16 {
        k1[i as usize] = i + 201;  // Key values 201-216
    }
    
    let mut n: [u8; 16] = [0u8; 16];
    for i in 0u8..16 {
        n[i as usize] = i + 101;  // Nonce values 101-116
    }

    // Test the 32-byte key expansion
    assert_eq!(
        salsa20k32(k0, k1, n),
        [
            69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, 98, 89, 144, 182,
            106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40, 126, 104, 197, 7, 225, 197, 153,
            31, 2, 102, 78, 76, 176, 84, 245, 246, 184, 177, 160, 133, 130, 6, 72, 149, 119, 192,
            195, 132, 236, 234, 103, 246, 74
        ]
    );
    
    // Test the 16-byte key expansion
    assert_eq!(
        salsa20k16(k0, n),
        [
            39, 173, 46, 248, 30, 200, 82, 17, 48, 67, 254, 239, 37, 18, 13, 247, 241, 200, 61,
            144, 10, 55, 50, 185, 6, 47, 246, 253, 143, 86, 187, 225, 134, 85, 110, 246, 161, 163,
            43, 235, 231, 94, 171, 51, 145, 214, 112, 29, 14, 232, 5, 16, 151, 140, 183, 141, 171,
            9, 122, 181, 104, 182, 177, 193
        ]
    );
}

/// Encrypts a message using Salsa20 with a 32-byte key.
/// 
/// This function expands the key into blocks using salsa20k32 with incrementing nonce values
/// and XORs the message with the generated keystream. The Salsa20 algorithm is a stream cipher,
/// so encryption is performed by XORing the plaintext with the keystream.
/// 
/// # Arguments
/// 
/// * `message` - The plaintext message to encrypt
/// * `k0` - The first half of the 32-byte key (16 bytes)
/// * `k1` - The second half of the 32-byte key (16 bytes)
/// 
/// # Returns
/// 
/// * The encrypted ciphertext as a vector of bytes
///
/// # Example
///
/// ```
/// use salsa20::{salsa20_encrypt, salsa20_decrypt};
///
/// // Create a test message
/// let message = b"This is a test message for Salsa20 encryption";
/// 
/// // Create key halves (in a real application, use a secure random number generator)
/// let k0 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
/// let k1 = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
/// 
/// // Encrypt the message
/// let ciphertext = salsa20_encrypt(message, k0, k1);
/// 
/// // Decrypt the ciphertext
/// let decrypted = salsa20_decrypt(&ciphertext, k0, k1);
/// 
/// // Verify that decryption recovers the original message
/// assert_eq!(decrypted, message);
/// ```
pub fn salsa20_encrypt(message: &[u8], k0: [u8; 16], k1: [u8; 16]) -> Vec<u8> {
    let mut ciphertext = vec![0u8; message.len()];
    let mut block_counter: u64 = 0;
    let mut position = 0;

    while position < message.len() {
        // Create nonce with block counter
        let mut nonce = [0u8; 16];
        let counter_bytes = block_counter.to_le_bytes();
        nonce[0..8].copy_from_slice(&counter_bytes);
        
        // Generate keystream block
        let keystream_block = salsa20k32(k0, k1, nonce);
        
        // XOR message with keystream block
        let remaining = message.len() - position;
        let block_size = remaining.min(64);
        
        for i in 0..block_size {
            ciphertext[position + i] = message[position + i] ^ keystream_block[i];
        }
        
        position += block_size;
        block_counter += 1;
    }
    
    ciphertext
}

/// Decrypts a ciphertext using Salsa20 with a 32-byte key.
/// 
/// Since Salsa20 is a stream cipher that uses XOR for encryption,
/// decryption is performed using the same operation as encryption.
/// The function simply generates the same keystream as during encryption
/// and XORs it with the ciphertext to recover the plaintext.
/// 
/// # Arguments
/// 
/// * `ciphertext` - The ciphertext to decrypt
/// * `k0` - The first half of the 32-byte key (16 bytes)
/// * `k1` - The second half of the 32-byte key (16 bytes)
/// 
/// # Returns
/// 
/// * The decrypted plaintext as a vector of bytes
/// 
/// # Example
/// 
/// ```
/// use salsa20::{salsa20_encrypt, salsa20_decrypt};
/// 
/// // Key components
/// let k0 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
/// let k1 = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
/// 
/// // Original message
/// let message = b"Secret message to be encrypted";
/// 
/// // Encrypt the message
/// let encrypted = salsa20_encrypt(message, k0, k1);
/// 
/// // Decrypt the message 
/// let decrypted = salsa20_decrypt(&encrypted, k0, k1);
/// 
/// // Verify decryption worked correctly
/// assert_eq!(&decrypted, message);
/// ```
pub fn salsa20_decrypt(ciphertext: &[u8], k0: [u8; 16], k1: [u8; 16]) -> Vec<u8> {
    // Decryption is the same as encryption with Salsa20
    // This is because XOR is its own inverse operation: (A XOR B) XOR B = A
    salsa20_encrypt(ciphertext, k0, k1)
}

/// Tests the encryption and decryption functionality with a 32-byte key
#[test]
fn test_salsa20_encryption_decryption() {
    // Test with a simple message
    let message = b"Hello, Salsa20 encryption test!";
    let mut k0 = [0u8; 16];
    let mut k1 = [0u8; 16];
    
    // Fill keys with test values
    for i in 0..16 {
        k0[i] = i as u8;
        k1[i] = (i + 100) as u8;
    }
    
    // Encrypt the message
    let ciphertext = salsa20_encrypt(message, k0, k1);
    
    // Ensure ciphertext is different from plaintext
    assert_ne!(&ciphertext, message);
    
    // Decrypt the ciphertext
    let decrypted = salsa20_decrypt(&ciphertext, k0, k1);
    
    // Ensure decryption recovers the original message
    assert_eq!(&decrypted, message);
    
    // Test with a long message that spans multiple blocks
    let long_message = vec![0x42u8; 200]; // 200 bytes of 0x42
    let ciphertext = salsa20_encrypt(&long_message, k0, k1);
    let decrypted = salsa20_decrypt(&ciphertext, k0, k1);
    assert_eq!(decrypted, long_message);
}

/// Encrypts a message using Salsa20 with a 16-byte key.
/// 
/// This function expands the key into blocks using salsa20k16 with incrementing nonce values
/// and XORs the message with the generated keystream. This variant uses a shorter 16-byte key,
/// which is repeated in the Salsa20 block according to the specification.
/// 
/// # Arguments
/// 
/// * `message` - The plaintext message to encrypt
/// * `key` - The 16-byte key
/// 
/// # Returns
/// 
/// * The encrypted ciphertext as a vector of bytes
///
/// # Example
///
/// ```
/// use salsa20::{salsa20_encrypt_k16, salsa20_decrypt_k16};
///
/// // Create a test message
/// let message = b"This is a test message for Salsa20 encryption with a 16-byte key";
/// 
/// // Create key (in a real application, use a secure random number generator)
/// let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
/// 
/// // Encrypt the message
/// let ciphertext = salsa20_encrypt_k16(message, key);
/// 
/// // Decrypt the ciphertext
/// let decrypted = salsa20_decrypt_k16(&ciphertext, key);
/// 
/// // Verify that decryption recovers the original message
/// assert_eq!(decrypted, message);
/// ```
pub fn salsa20_encrypt_k16(message: &[u8], key: [u8; 16]) -> Vec<u8> {
    let mut ciphertext = vec![0u8; message.len()];
    let mut block_counter: u64 = 0;
    let mut position = 0;

    while position < message.len() {
        // Create nonce with block counter
        let mut nonce = [0u8; 16];
        let counter_bytes = block_counter.to_le_bytes();
        nonce[0..8].copy_from_slice(&counter_bytes);
        
        // Generate keystream block
        let keystream_block = salsa20k16(key, nonce);
        
        // XOR message with keystream block
        let remaining = message.len() - position;
        let block_size = remaining.min(64);
        
        for i in 0..block_size {
            ciphertext[position + i] = message[position + i] ^ keystream_block[i];
        }
        
        position += block_size;
        block_counter += 1;
    }
    
    ciphertext
}

/// Decrypts a ciphertext using Salsa20 with a 16-byte key.
/// 
/// Since Salsa20 is a stream cipher that uses XOR for encryption,
/// decryption is performed using the same operation as encryption.
/// The function simply generates the same keystream as during encryption
/// and XORs it with the ciphertext to recover the plaintext.
/// 
/// # Arguments
/// 
/// * `ciphertext` - The ciphertext to decrypt
/// * `key` - The 16-byte key
/// 
/// # Returns
/// 
/// * The decrypted plaintext as a vector of bytes
/// 
/// # Example
/// 
/// ```
/// use salsa20::{salsa20_encrypt_k16, salsa20_decrypt_k16};
/// 
/// // Original message and key
/// let message = b"This is a test message";
/// let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
/// 
/// // Encrypt
/// let encrypted = salsa20_encrypt_k16(message, key);
/// 
/// // Decrypt
/// let decrypted = salsa20_decrypt_k16(&encrypted, key);
/// 
/// // Verify decryption worked correctly
/// assert_eq!(&decrypted, message);
/// ```
pub fn salsa20_decrypt_k16(ciphertext: &[u8], key: [u8; 16]) -> Vec<u8> {
    // Decryption is the same as encryption with Salsa20
    // This is because XOR is its own inverse operation: (A XOR B) XOR B = A
    salsa20_encrypt_k16(ciphertext, key)
}

/// Tests the encryption and decryption functionality with a 16-byte key
#[test]
fn test_salsa20_k16_encryption_decryption() {
    // Test with a simple message
    let message = b"Hello, Salsa20 encryption with 16-byte key!";
    let mut key = [0u8; 16];
    
    // Fill key with test values
    for i in 0..16 {
        key[i] = i as u8;
    }
    
    // Encrypt the message
    let ciphertext = salsa20_encrypt_k16(message, key);
    
    // Ensure ciphertext is different from plaintext
    assert_ne!(&ciphertext, message);
    
    // Decrypt the ciphertext
    let decrypted = salsa20_decrypt_k16(&ciphertext, key);
    
    // Ensure decryption recovers the original message
    assert_eq!(&decrypted, message);
    
    // Test with a long message that spans multiple blocks
    let long_message = vec![0x42u8; 200]; // 200 bytes of 0x42
    let ciphertext = salsa20_encrypt_k16(&long_message, key);
    let decrypted = salsa20_decrypt_k16(&ciphertext, key);
    assert_eq!(decrypted, long_message);
}
