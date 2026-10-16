use ml_dsa::{ExpandedSigningKey, Generate, KeyExport, KeyInit, MlDsa44, Verifier, VerifyingKey};
use std::time::Instant;

fn main() {
    let generated = ml_dsa::SigningKey::<MlDsa44>::generate();
    let expanded_key = ExpandedSigningKey::<MlDsa44>::from_seed(&generated.to_seed());
    let verifying_key = expanded_key.verifying_key();
    let verifying_key_bytes = verifying_key.to_bytes();
    let message = b"benchmark message for ML-DSA-44";
    let signature = expanded_key
        .sign_deterministic(message, &[])
        .expect("ML-DSA-44 signing failed");
    let iterations = 100;

    println!("public key size: {} bytes", verifying_key_bytes.len());

    let start = Instant::now();
    for _ in 0..iterations {
        verifying_key.verify(message, &signature).unwrap();
    }
    let cached_elapsed = start.elapsed();
    println!(
        "verify with cached key: {:?} total, {:?} average",
        cached_elapsed,
        cached_elapsed / iterations
    );

    let start = Instant::now();
    for _ in 0..iterations {
        let key = VerifyingKey::<MlDsa44>::new(&verifying_key_bytes);
        key.verify(message, &signature).unwrap();
    }
    let reconstructed_elapsed = start.elapsed();
    println!(
        "reconstruct public key + verify: {:?} total, {:?} average",
        reconstructed_elapsed,
        reconstructed_elapsed / iterations
    );

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(VerifyingKey::<MlDsa44>::new(&verifying_key_bytes));
    }
    let reconstruction_elapsed = start.elapsed();
    println!(
        "reconstruct public key only: {:?} total, {:?} average",
        reconstruction_elapsed,
        reconstruction_elapsed / iterations
    );
}
