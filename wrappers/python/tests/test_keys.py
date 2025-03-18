import json
import hashlib

import pytest

from aries_askar import (
    KeyAlg,
    Key,
    SeedMethod,
)
from aries_askar.types import KeyBackend


def test_get_supported_backends():
    backends = Key.get_supported_backends()

    assert backends == [str(KeyBackend.Software)]


@pytest.mark.parametrize(
    "key_alg",
    [KeyAlg.A128CBC_HS256, KeyAlg.A128GCM, KeyAlg.XC20P],
)
def test_symmetric(key_alg: KeyAlg):
    key = Key.generate(key_alg)
    assert key.algorithm == key_alg

    data = b"test message"
    nonce = key.aead_random_nonce()
    params = key.aead_params()
    assert isinstance(params.nonce_length, int)
    assert isinstance(params.tag_length, int)
    enc = key.aead_encrypt(data, nonce=nonce, aad=b"aad")
    dec = key.aead_decrypt(enc, nonce=nonce, aad=b"aad")
    assert data == bytes(dec)

    jwk = json.loads(key.get_jwk_secret())
    assert jwk["kty"] == "oct"
    assert KeyAlg.from_key_alg(jwk["alg"].lower().replace("-", "")) == key_alg
    assert jwk["k"]


def test_bls_keygen():
    key = Key.from_seed(
        KeyAlg.BLS12_381_G1G2,
        b"testseed000000000000000000000001",
        method=SeedMethod.BlsKeyGen,
    )
    assert key.get_jwk_public(KeyAlg.BLS12_381_G1) == (
        '{"crv":"BLS12381_G1","kty":"OKP","x":'
        '"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1HrV"}'
    )
    assert key.get_jwk_public(KeyAlg.BLS12_381_G2) == (
        '{"crv":"BLS12381_G2","kty":"OKP",'
        '"x":"iZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4'
        'rbkAo-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d"}'
    )
    assert key.get_jwk_public() == (
        '{"crv":"BLS12381_G1G2","kty":"OKP",'
        '"x":"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1H'
        "rViZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4rbk"
        'Ao-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d"}'
    )


def test_ed25519():
    key = Key.generate(KeyAlg.ED25519)
    assert key.algorithm == KeyAlg.ED25519
    message = b"test message"
    sig = key.sign_message(message)
    assert key.verify_signature(message, sig)
    x25519_key = key.convert_key(KeyAlg.X25519)

    x25519_key_2 = Key.generate(KeyAlg.X25519)
    kex = x25519_key.key_exchange(KeyAlg.XC20P, x25519_key_2)
    assert isinstance(kex, Key)

    jwk = json.loads(key.get_jwk_public())
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"

    jwk = json.loads(key.get_jwk_secret())
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"


@pytest.mark.parametrize(
    "key_alg",
    [KeyAlg.K256, KeyAlg.P256, KeyAlg.P384],
)
def test_ec_curves(key_alg: KeyAlg):
    key = Key.generate(key_alg)
    assert key.algorithm == key_alg
    message = b"test message"
    sig = key.sign_message(message)
    assert key.verify_signature(message, sig)

    jwk = json.loads(key.get_jwk_public())
    assert jwk["kty"] == "EC"
    assert jwk["crv"]
    assert jwk["x"]
    assert jwk["y"]

    jwk = json.loads(key.get_jwk_secret())
    assert jwk["kty"] == "EC"
    assert jwk["crv"]
    assert jwk["x"]
    assert jwk["y"]
    assert jwk["d"]


def test_sign_prehashed():
    key = Key.generate("p256")
    message = hashlib.sha384(b"test message").digest()
    sig = key.sign_message(message, "es256ph")
    assert key.verify_signature(message, sig, "es256ph")
