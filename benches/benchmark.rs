use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distr::Alphanumeric, RngExt};

use aries_askar::{
    future::block_on,
    kms::{KeyAlg, LocalKey},
    Store, StoreKeyMethod,
};

const ERR_RAW_KEY: &str = "Error creating raw store key";
const ERR_SESSION: &str = "Error creating store session";
const ERR_OPEN: &str = "Error opening test store instance";
const ERR_REQ_ROW: &str = "Row required";
const ERR_CLOSE: &str = "Error closing test store instance";

const ROOT_SEED: [u8; 32] = [0x55; 32];

/// Initalize a clean DB for benchmarking
fn initialize_database() -> Store {
    block_on(async {
        let db_url = match std::env::var("POSTGRES_URL") {
            Ok(p) if !p.is_empty() => p,
            _ => "sqlite://:memory:".to_string(),
        };
        let pass_key = Store::new_raw_key(Some(&ROOT_SEED)).expect(ERR_RAW_KEY);

        Store::provision(
            &db_url,
            StoreKeyMethod::RawKey,
            pass_key,
            Some("askar-bench".to_string()),
            true,
        )
        .await
        .expect(ERR_OPEN)
    })
}

/// Inject `n` number of keys and profiles into the DB
fn populate_database_keys_profiles(db: &Store, n: u64) {
    block_on(async {
        let mut conn = db.session(None).await.expect(ERR_SESSION);

        for _ in 0..n {
            let keypair = LocalKey::generate_with_rng(KeyAlg::Ed25519, false)
                .expect("Error creating keypair");
            let key_name = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect::<String>();
            let metadata = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect::<String>();

            conn.insert_key(
                &key_name,
                &keypair,
                Some(metadata.as_str()),
                None,
                None,
                None,
            )
            .await
            .expect("Error inserting key");

            let found = conn
                .fetch_key(&key_name, false)
                .await
                .expect("Error fetching key")
                .expect(ERR_REQ_ROW);
            assert_eq!(found.algorithm(), Some(KeyAlg::Ed25519.as_str()));
            assert_eq!(found.name(), key_name);
            assert_eq!(found.metadata(), Some(metadata.as_str()));
            assert!(found.is_local());
            found.load_local_key().expect("Error loading key");

            db.create_profile(None)
                .await
                .expect("Error creating profile");
        }

        drop(conn);
    });
}

fn criterion_benchmarks(c: &mut Criterion) {
    let db = initialize_database();
    populate_database_keys_profiles(&db, 10_000);

    c.bench_function("benchmark_database", |b| {
        b.iter(|| {
            let db = db.clone();
            populate_database_keys_profiles(&db, 1);
        });
    });

    block_on(async { db.close().await.expect(ERR_CLOSE) });
}

criterion_group!(
    name = benchmarks;
    config = Criterion::default().sample_size(1_000);
    targets = criterion_benchmarks
);
criterion_main!(benchmarks);
