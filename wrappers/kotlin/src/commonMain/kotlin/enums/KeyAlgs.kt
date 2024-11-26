package askar.enums

enum class KeyAlgs(val alg: String) {
    AesA128Gcm("a128gcm"),
    AesA256Gcm("a256gcm"),
    AesA128CbcHs256("a128cbchs256"),
    AesA256CbcHs512("a256cbchs512"),
    AesA128Kw("a128kw"),
    AesA256Kw("a256kw"),
    Bls12381G1("bls12381g1"),
    Bls12381G2("bls12381g2"),
    Bls12381G1G2("bls12381g1g2"),
    Chacha20C20P("c20p"),
    Chacha20XC20P("xc20p"),
    Ed25519("ed25519"),
    X25519("x25519"),
    EcSecp256k1("k256"),
    EcSecp256r1("p256"),
}

fun keyAlgFromString(algorithm: String): KeyAlgs {
    for(alg in KeyAlgs.values())
        if(alg.alg == algorithm)
            return alg
    throw Error("Algorithm $algorithm is not a supported algorithm")
}

