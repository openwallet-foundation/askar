use ml_dsa::{ExpandedSigningKey, Generate, MlDsa44, Seed};
use std::{hint::black_box, time::Instant};

const ITERATIONS: u32 = 1000;

#[allow(deprecated)]
fn reconstruct_from_expanded(
    bytes: &ml_dsa::ExpandedSigningKeyBytes<MlDsa44>,
) -> ExpandedSigningKey<MlDsa44> {
    ExpandedSigningKey::<MlDsa44>::from_expanded(bytes)
}

fn measure(label: &str, mut operation: impl FnMut()) {
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        operation();
    }
    let elapsed = start.elapsed();
    println!(
        "{label}: {:?} total, {:?} average ({ITERATIONS} iterations)",
        elapsed,
        elapsed / ITERATIONS
    );
}

fn main() {
    let generated = ml_dsa::SigningKey::<MlDsa44>::generate();
    let seed: Seed = generated.to_seed();
    let expanded_key = ExpandedSigningKey::<MlDsa44>::from_seed(&seed);
    #[allow(deprecated)]
    let expanded_bytes = expanded_key.to_expanded();
    let message = b"benchmark message for ML-DSA-44";

    println!("seed storage: {} bytes", seed.len());
    println!("expanded-key storage: {} bytes", expanded_bytes.len());

    measure("reconstruct expanded key from seed", || {
        black_box(ExpandedSigningKey::<MlDsa44>::from_seed(black_box(&seed)));
    });
    measure(
        "reconstruct expanded key from stored expanded bytes (deprecated decoder)",
        || {
            black_box(reconstruct_from_expanded(black_box(&expanded_bytes)));
        },
    );
    measure("seed reconstruction + deterministic signing", || {
        let key = ExpandedSigningKey::<MlDsa44>::from_seed(black_box(&seed));
        black_box(key.sign_deterministic(black_box(message), &[]).unwrap());
    });
    measure(
        "expanded-byte reconstruction + deterministic signing",
        || {
            let key = reconstruct_from_expanded(black_box(&expanded_bytes));
            black_box(key.sign_deterministic(black_box(message), &[]).unwrap());
        },
    );
    measure("cached expanded-key deterministic signing", || {
        black_box(
            expanded_key
                .sign_deterministic(black_box(message), &[])
                .unwrap(),
        );
    });
}
