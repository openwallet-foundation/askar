use ml_dsa::{ExpandedSigningKey, Generate, MlDsa44, Seed, Signature, Verifier};
#[cfg(feature = "getrandom")]
use rand::rngs::SysRng;

fn main() {
    let signing_key = ml_dsa::SigningKey::<MlDsa44>::generate();
    let seed = signing_key.to_seed();
    let expanded_key = ExpandedSigningKey::<MlDsa44>::from_seed(&seed);
    let imported_key = ExpandedSigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
    let verifying_key = expanded_key.verifying_key();
    let message = b"post-quantum verifiable credential payload";

    assert_eq!(expanded_key, imported_key);

    let deterministic_signature = expanded_key
        .sign_deterministic(message, &[])
        .expect("deterministic ML-DSA-44 signing failed");
    let repeated_signature = expanded_key
        .sign_deterministic(message, &[])
        .expect("deterministic ML-DSA-44 signing failed");
    assert_eq!(deterministic_signature, repeated_signature);
    verifying_key
        .verify(message, &deterministic_signature)
        .expect("ML-DSA-44 signature verification failed");
    assert!(verifying_key
        .verify(b"modified message", &deterministic_signature)
        .is_err());

    let other_key = ExpandedSigningKey::<MlDsa44>::from_seed(&Seed::from([1u8; 32]));
    assert!(other_key
        .verifying_key()
        .verify(message, &deterministic_signature)
        .is_err());

    let mut altered_bytes = deterministic_signature.encode();
    altered_bytes[0] ^= 1;
    let altered_signature = Signature::<MlDsa44>::decode(&altered_bytes)
        .expect("modified signature encoding should remain structurally valid");
    assert!(verifying_key.verify(message, &altered_signature).is_err());

    #[cfg(feature = "getrandom")]
    {
        let mut rng = SysRng;
        let randomized_signature = expanded_key
            .sign_randomized(message, &[], &mut rng)
            .expect("randomized ML-DSA-44 signing failed");
        verifying_key
            .verify(message, &randomized_signature)
            .expect("randomized ML-DSA-44 signature verification failed");
    }

    println!("ML-DSA-44 generation, seed import, signing, and verification OK");
}
