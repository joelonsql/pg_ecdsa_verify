//! ECDSA Signature verification algorithm implemented in Rust  
//!
//! This code is based on v2.2.0 of the [starkbank-ecdsa] Python library
//! developed by Star Bank [Star Bank].
//!
//! The [`ecdsa_verify`](fn.ecdsa_verify.html) function signature is the same as
//! the PostgreSQL extension [pg-ecdsa] written in C, allowing this crate to be
//! a compatible drop-in replacement when Rust is desired instead of C.
//!
//! [starkbank-ecdsa]: https://github.com/starkbank/ecdsa-python/commit/9acdc661b7acde453b9bd6b20c57b88d5a3bf7e3
//! [Star Bank]: https://starkbank.com/
//! [pg-ecdsa]: https://github.com/ameensol/pg-ecdsa
use pgrx::prelude::*;
use ecdsa_verify_lib::{Point3D, EcdsaSignature, verify, secp256r1, secp256k1};
use sha2::{Digest, Sha256};
use num_bigint::BigInt;
use num_traits::Zero;
use std::ops::Rem;

pgrx::pg_module_magic!();

/// Decompresses a 33-byte compressed ECDSA public key to a 64-byte uncompressed key.
///
/// A compressed public key consists of:
/// - 1 byte prefix (0x02 or 0x03) indicating whether the y-coordinate is even or odd
/// - 32 bytes for the x-coordinate
///
/// This function recovers the full y-coordinate using the curve equation: y² = x³ + ax + b (mod p)
///
/// # Arguments
///
/// * `compressed_key` - A 33-byte compressed public key
/// * `curve_name` - The name of the elliptic curve ("secp256r1" or "secp256k1")
///
/// # Returns
///
/// * `Vec<u8>` - A 64-byte uncompressed public key (32 bytes x + 32 bytes y)
///
/// # Panics
///
/// * If the compressed key is not 33 bytes
/// * If the prefix byte is not 0x02 or 0x03
/// * If the x-coordinate does not correspond to a valid point on the curve
fn decompress_public_key(compressed_key: &[u8], curve_name: &str) -> Vec<u8> {
    if compressed_key.len() != 33 {
        panic!("Compressed public key must be 33 bytes, got {}", compressed_key.len());
    }

    let prefix = compressed_key[0];
    if prefix != 0x02 && prefix != 0x03 {
        panic!("Invalid compressed key prefix: 0x{:02x}", prefix);
    }

    let x_bytes = &compressed_key[1..33];
    let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes);

    // Get curve parameters
    let (a, b, p) = match curve_name {
        "secp256r1" => {
            // secp256r1 parameters
            let a = BigInt::from(-3i32);
            let b = BigInt::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap();
            let p = BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap();
            (a, b, p)
        }
        "secp256k1" => {
            // secp256k1 parameters
            let a = BigInt::from(0i32);
            let b = BigInt::from(7i32);
            let p = BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16).unwrap();
            (a, b, p)
        }
        _ => panic!("Unsupported curve: {}", curve_name),
    };

    // Calculate y² = x³ + ax + b (mod p)
    let x_squared = (&x * &x).rem(&p);
    let x_cubed = (&x_squared * &x).rem(&p);
    let ax = (&a * &x).rem(&p);
    let y_squared = (&x_cubed + &ax + &b).rem(&p);

    // Compute modular square root using Tonelli-Shanks algorithm
    let y = tonelli_shanks(&y_squared, &p);

    // Determine which root to use based on the prefix
    let y_is_even = (&y & BigInt::from(1i32)) == BigInt::from(0i32);
    let should_be_even = prefix == 0x02;

    let final_y = if y_is_even == should_be_even {
        y
    } else {
        (&p - &y).rem(&p)
    };

    // Convert to bytes
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&x.to_bytes_be().1);
    let y_bytes = final_y.to_bytes_be().1;
    // Pad y to 32 bytes if necessary
    if y_bytes.len() < 32 {
        result.extend_from_slice(&vec![0u8; 32 - y_bytes.len()]);
    }
    result.extend_from_slice(&y_bytes);

    result
}

/// Tonelli-Shanks algorithm for computing modular square root
/// Computes r such that r² ≡ n (mod p)
fn tonelli_shanks(n: &BigInt, p: &BigInt) -> BigInt {
    if n == &BigInt::from(0i32) {
        return BigInt::from(0i32);
    }

    // Check if n is a quadratic residue
    let exp = (p - BigInt::from(1i32)) / BigInt::from(2i32);
    if n.modpow(&exp, p) != BigInt::from(1i32) {
        panic!("No modular square root exists");
    }

    // Factor out powers of 2 from p - 1
    let mut q = p - BigInt::from(1i32);
    let mut s = 0i32;
    while (&q & BigInt::from(1i32)) == BigInt::from(0i32) {
        q = &q >> 1;
        s += 1;
    }

    if s == 1 {
        return n.modpow(&((p + BigInt::from(1i32)) / BigInt::from(4i32)), p);
    }

    // Find a quadratic non-residue z
    let mut z = BigInt::from(2i32);
    loop {
        let exp = (p - BigInt::from(1i32)) / BigInt::from(2i32);
        if z.modpow(&exp, p) == (p - BigInt::from(1i32)) {
            break;
        }
        z = &z + BigInt::from(1i32);
    }

    let mut m = s;
    let mut c = z.modpow(&q, p);
    let exp = (&q + BigInt::from(1i32)) / BigInt::from(2i32);
    let mut t = n.modpow(&exp, p);
    let mut r = n.modpow(&exp, p);

    loop {
        if &t == &BigInt::from(1i32) {
            return r;
        }

        // Find the least i such that t^(2^i) = 1
        let mut i = 1i32;
        let mut temp = (&t * &t).rem(p);
        while temp != BigInt::from(1i32) && i < m {
            temp = (&temp * &temp).rem(p);
            i += 1;
        }

        let b = c.clone();
        for _ in 0..(m - i - 1) {
            c = (&b * &b).rem(p);
        }

        m = i;
        r = (&r * &b).rem(p);
        t = (&t * &c * &c).rem(p);
        c = (&b * &b).rem(p);
    }
}

/// Verifies an ECDSA signature for a given input data using a specified curve and hash function.
///
/// Supports both 64-byte uncompressed public keys and 33-byte compressed public keys.
///
/// # Arguments
///
/// * `public_key` - The public key in bytes format (33 bytes compressed or 64 bytes uncompressed).
/// * `input_data` - The input data to verify.
/// * `signature` - The signature in bytes format.
/// * `hash_func` - The name of the hash function to use.
/// * `curve_name` - The name of the elliptic curve to use.
///
/// Supported values for `hash_func`:
/// - "sha256"
///
/// Supported values for `curve_name`:
/// - "secp256r1"
/// - "secp256k1"
///
/// # Returns
///
/// * `bool` - `true` if the signature is valid, `false` otherwise.
///
/// # Panics
///
/// * If an unsupported curve name or hash function is provided.
/// * If the public key is not 33 or 64 bytes.
///
/// # Example
///
/// ```
/// use pg_ecdsa_verify::ecdsa_verify;
///
/// let public_key = hex::decode("7fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8fdb9983b319469d35e719a3b93e1ac292854cd3ff2ad50898681b0a32ffbcbc6a").unwrap();
/// let input_data = hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000117bd119a942a38b92bfc3b90a21f7eaa37fe1a7fa0abe27fd15dd20683b14d54").unwrap();
/// let signature = hex::decode("10fab01307f3eed59bc11601265efaab524b50d017bd9cdfeec4f61b01caa8d669c6e9f8d9bcbdba4e5478cb75b084332d51b0be2c21701b157c7c87abb98057").unwrap();
/// let hash_func = "sha256";
/// let curve_name = "secp256r1";
///
/// assert!(ecdsa_verify(&public_key, &input_data, &signature, hash_func, curve_name));
/// ```
#[pg_extern]
pub fn ecdsa_verify(
    public_key: &[u8],
    input_data: &[u8],
    signature: &[u8],
    hash_func: &str,
    curve_name: &str,
) -> bool {
    let curve = match curve_name {
        "secp256r1" => secp256r1(),
        "secp256k1" => secp256k1(),
        _ => panic!("Unsupported curve: {}", curve_name),
    };

    let message_hash = match hash_func {
        "sha256" => Sha256::digest(input_data).to_vec(),
        _ => panic!("Unsupported hash function: {}", hash_func),
    };

    let sig = EcdsaSignature {
        r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &signature[..32]),
        s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &signature[32..]),
    };

    // Handle both compressed (33 bytes) and uncompressed (64 bytes) public keys
    let uncompressed_key = match public_key.len() {
        33 => decompress_public_key(public_key, curve_name),
        64 => public_key.to_vec(),
        _ => panic!("Public key must be 33 bytes (compressed) or 64 bytes (uncompressed), got {}", public_key.len()),
    };

    let public_key = Point3D {
        x: BigInt::from_bytes_be(num_bigint::Sign::Plus, &uncompressed_key[..32]),
        y: BigInt::from_bytes_be(num_bigint::Sign::Plus, &uncompressed_key[32..]),
        z: BigInt::zero(),
    };

    verify(&message_hash, &sig, &public_key, &curve)
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use super::*;

    #[pg_test]
    fn test_ecdsa_verify() {
        let public_key = hex::decode("7fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8fdb9983b319469d35e719a3b93e1ac292854cd3ff2ad50898681b0a32ffbcbc6a").unwrap();
        let input_data = hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000117bd119a942a38b92bfc3b90a21f7eaa37fe1a7fa0abe27fd15dd20683b14d54").unwrap();
        let signature = hex::decode("10fab01307f3eed59bc11601265efaab524b50d017bd9cdfeec4f61b01caa8d669c6e9f8d9bcbdba4e5478cb75b084332d51b0be2c21701b157c7c87abb98057").unwrap();
        let hash_func = "sha256";
        let curve_name = "secp256r1";

        assert!(ecdsa_verify(&public_key, &input_data, &signature, hash_func, curve_name));
    }

    #[pg_test]
    fn test_invalid_signature_ecdsa_verify() {
        let public_key = hex::decode("7fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8fdb9983b319469d35e719a3b93e1ac292854cd3ff2ad50898681b0a32ffbcbc6a").unwrap();
        let input_data = hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000117bd119a942a38b92bfc3b90a21f7eaa37fe1a7fa0abe27fd15dd20683b14d54").unwrap();
        let signature = hex::decode("10fab01307f3eed59bc11601265efaab524b50d017bd9cdfeec4f61b01caa8d669c6e9f8d9bcbdba4e5478cb75b084332d51b0be2c21701b157c7c87abb98056").unwrap();
        let hash_func = "sha256";
        let curve_name = "secp256r1";

        assert!(!ecdsa_verify(&public_key, &input_data, &signature, hash_func, curve_name));
    }

    #[pg_test]
    fn test_ecdsa_verify_compressed_key() {
        // This is the compressed version of the public key from test_ecdsa_verify
        // Original uncompressed: 7fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8fdb9983b319469d35e719a3b93e1ac292854cd3ff2ad50898681b0a32ffbcbc6a
        // Compressed (even y): 027fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8f
        let compressed_public_key = hex::decode("027fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8f").unwrap();
        let input_data = hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000117bd119a942a38b92bfc3b90a21f7eaa37fe1a7fa0abe27fd15dd20683b14d54").unwrap();
        let signature = hex::decode("10fab01307f3eed59bc11601265efaab524b50d017bd9cdfeec4f61b01caa8d669c6e9f8d9bcbdba4e5478cb75b084332d51b0be2c21701b157c7c87abb98057").unwrap();
        let hash_func = "sha256";
        let curve_name = "secp256r1";

        assert!(ecdsa_verify(&compressed_public_key, &input_data, &signature, hash_func, curve_name));
    }

    #[pg_test]
    fn test_ecdsa_verify_compressed_key_k1() {
        // Checking secp256k1 expansion
        // Original uncompressed: 67e60b9a1434d2c3e8143bdfead8e3690e3a08c57bdbeb7c06a3126d55773db7201f750ec64254744ae54b00fda9c570fe2951c701ec647f909a4fb1753b0956
        // Compressed (even y): 0267e60b9a1434d2c3e8143bdfead8e3690e3a08c57bdbeb7c06a3126d55773db7
        let compressed_public_key = hex::decode("0267e60b9a1434d2c3e8143bdfead8e3690e3a08c57bdbeb7c06a3126d55773db7").unwrap();
        let input_data = hex::decode("3132333435363738393130").unwrap();
        let signature = hex::decode("2d5022e57c5f7984cec2c7c24b5446becd72b6d3e92a8b0928183386ba2cfd6b7f43e2b876f284945fad81a5fc7431bb4a8910e515ed7e43cec0439b1ea62669").unwrap();
        let hash_func = "sha256";
        let curve_name = "secp256k1";

        assert!(ecdsa_verify(&compressed_public_key, &input_data, &signature, hash_func, curve_name));
    }

    #[pg_test]
    fn test_invalid_ecdsa_verify_compressed_key_k1() {
        let compressed_public_key = hex::decode("0367e60b9a1434d2c3e8143bdfead8e3690e3a08c57bdbeb7c06a3126d55773db7").unwrap();
        let input_data = hex::decode("3132333435363738393130").unwrap();
        let signature = hex::decode("2d5022e57c5f7984cec2c7c24b5446becd72b6d3e92a8b0928183386ba2cfd6b7f43e2b876f284945fad81a5fc7431bb4a8910e515ed7e43cec0439b1ea62669").unwrap();
        let hash_func = "sha256";
        let curve_name = "secp256k1";

        assert!(!ecdsa_verify(&compressed_public_key, &input_data, &signature, hash_func, curve_name));
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
