use std::hint::black_box;

use askar_crypto::{
    alg::{
        aes::{A128CbcHs256, A128Gcm, A256CbcHs512, A256Gcm, AesKey},
        chacha20::{Chacha20Key, C20P, XC20P},
        AnyKey, AnyKeyCreate, Chacha20Types, KeyAlg,
    },
    buffer::{SecretBytes, WriteBuffer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    random::fill_random,
    repr::KeyGen,
};

use criterion::Criterion;

fn criterion_benchmark(c: &mut Criterion) {
    const MSG_SIZE: usize = 2000000;
    const ALLOC_SIZE: usize = MSG_SIZE + 512;

    let mut message = vec![0u8; MSG_SIZE];
    fill_random(&mut message[..]);
    let message = message.as_slice();

    c.bench_function("random nonce", move |b| {
        b.iter(AesKey::<A128Gcm>::random_nonce)
    });
    c.bench_function("aes128gcm encrypt", move |b| {
        let key = AesKey::<A128Gcm>::random().unwrap();
        let nonce = AesKey::<A128Gcm>::random_nonce();
        let mut buffer = Vec::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.extend_from_slice(black_box(message));
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
        })
    });
    c.bench_function("aes256gcm encrypt", move |b| {
        let key = AesKey::<A256Gcm>::random().unwrap();
        let nonce = AesKey::<A256Gcm>::random_nonce();
        let mut buffer = Vec::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.extend_from_slice(black_box(message));
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
        })
    });

    c.bench_function("aes128cbc-hs256 encrypt", move |b| {
        let key = AesKey::<A128CbcHs256>::random().unwrap();
        let nonce = AesKey::<A128CbcHs256>::random_nonce();
        let mut buffer = Vec::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.extend_from_slice(black_box(message));
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
        })
    });
    c.bench_function("aes256cbc-hs512 encrypt", move |b| {
        let key = AesKey::<A256CbcHs512>::random().unwrap();
        let nonce = AesKey::<A256CbcHs512>::random_nonce();
        let mut buffer = Vec::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.extend_from_slice(black_box(message));
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
        })
    });

    c.bench_function("chacha20-poly1305 encrypt", move |b| {
        let key = Chacha20Key::<C20P>::random().unwrap();
        let nonce = Chacha20Key::<C20P>::random_nonce();
        let mut buffer = Vec::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.extend_from_slice(black_box(message));
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
        })
    });
    c.bench_function("xchacha20-poly1305 encrypt", move |b| {
        let key = Chacha20Key::<XC20P>::random().unwrap();
        let nonce = Chacha20Key::<XC20P>::random_nonce();
        let mut buffer = Vec::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.extend_from_slice(black_box(message));
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
        })
    });

    // test overhead of SecretBytes
    c.bench_function("chacha20-poly1305 encrypt alloc", move |b| {
        let key = Chacha20Key::<C20P>::random().unwrap();
        let nonce = Chacha20Key::<C20P>::random_nonce();
        let mut buffer = SecretBytes::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.buffer_write(black_box(message)).unwrap();
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
        })
    });

    // test overhead of AnyKey
    c.bench_function("chacha20-poly1305 encrypt as any", move |b| {
        let key = Box::<AnyKey>::random(KeyAlg::Chacha20(Chacha20Types::C20P)).unwrap();
        let mut nonce = [0u8; 255];
        let nonce_len = key.aead_params().nonce_length;
        fill_random(&mut nonce[..nonce_len]);
        let mut buffer = Vec::with_capacity(ALLOC_SIZE);
        b.iter(|| {
            buffer.clear();
            buffer.extend_from_slice(black_box(message));
            key.encrypt_in_place(&mut buffer, &nonce[..nonce_len], &[])
                .unwrap();
        })
    });
}

criterion::criterion_group!(benches, criterion_benchmark);
criterion::criterion_main!(benches);
