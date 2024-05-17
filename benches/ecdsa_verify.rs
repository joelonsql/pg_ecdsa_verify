#![feature(test)]

extern crate test;

use test::Bencher;
use pg_ecdsa_verify::ecdsa_verify;

#[bench]
fn bench_ecdsa_verify(b: &mut Bencher) {
    let public_key = hex::decode("7fa92dd0666eee7c13ddb7b6249b0c8f9fba4360857c4e15d2fc634a2b5a1f8fdb9983b319469d35e719a3b93e1ac292854cd3ff2ad50898681b0a32ffbcbc6a").unwrap();
    let input_data = hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000117bd119a942a38b92bfc3b90a21f7eaa37fe1a7fa0abe27fd15dd20683b14d54").unwrap();
    let signature = hex::decode("10fab01307f3eed59bc11601265efaab524b50d017bd9cdfeec4f61b01caa8d669c6e9f8d9bcbdba4e5478cb75b084332d51b0be2c21701b157c7c87abb98057").unwrap();
    let hash_func = "sha256";
    let curve_name = "secp256r1";

    b.iter(|| {
        assert!(ecdsa_verify(&public_key, &input_data, &signature, hash_func, curve_name));
    });
}
