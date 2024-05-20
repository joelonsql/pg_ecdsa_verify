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

pgrx::pg_module_magic!();

#[pg_schema]
pub mod ecdsa_verify {
    use super::*;
    use ecdsa_verify_lib::{Point3D, EcdsaSignature, verify, secp256r1, secp256k1};
    use sha2::{Digest, Sha256};
    use num_bigint::BigInt;
    use num_traits::Zero;

    /// Verifies an ECDSA signature for a given input data using a specified curve and hash function.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key in bytes format.
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
    /// assert!(ecdsa_verify::ecdsa_verify(&public_key, &input_data, &signature, hash_func, curve_name));
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

        let public_key = Point3D {
            x: BigInt::from_bytes_be(num_bigint::Sign::Plus, &public_key[..32]),
            y: BigInt::from_bytes_be(num_bigint::Sign::Plus, &public_key[32..]),
            z: BigInt::zero(),
        };

        verify(&message_hash, &sig, &public_key, &curve)
    }

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

        assert!(ecdsa_verify::ecdsa_verify(&public_key, &input_data, &signature, hash_func, curve_name));
    }

    #[pg_test]
    fn test_invalid_signature_ecdsa_verify() {
        let public_key = hex::decode("7fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8fdb9983b319469d35e719a3b93e1ac292854cd3ff2ad50898681b0a32ffbcbc6a").unwrap();
        let input_data = hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000117bd119a942a38b92bfc3b90a21f7eaa37fe1a7fa0abe27fd15dd20683b14d54").unwrap();
        let signature = hex::decode("10fab01307f3eed59bc11601265efaab524b50d017bd9cdfeec4f61b01caa8d669c6e9f8d9bcbdba4e5478cb75b084332d51b0be2c21701b157c7c87abb98056").unwrap();
        let hash_func = "sha256";
        let curve_name = "secp256r1";

        assert!(!ecdsa_verify::ecdsa_verify(&public_key, &input_data, &signature, hash_func, curve_name));
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
