from enum import Enum
from typing import Optional


class KeyAlg(Enum):
    A128GCM = "a128gcm"
    A256GCM = "a256gcm"
    A128CBC_HS256 = "a128cbchs256"
    A256CBC_HS512 = "a256cbchs512"
    A128KW = "a128kw"
    A256KW = "a256kw"
    BLS12_381_G1 = "bls12381g1"
    BLS12_381_G2 = "bls12381g2"
    C20P = "c20p"
    XC20P = "xc20p"
    ED25519 = "ed25519"
    X25519 = "x25519"
    K256 = "k256"
    P256 = "p256"
    P384 = "p384"

    @classmethod
    def from_key_alg(cls, alg: str) -> Optional["KeyAlg"]:
        """Get KeyAlg instance from the algorithm identifier."""
        for cmp_alg in KeyAlg:
            if cmp_alg.value == alg:
                return cmp_alg

        return None


class KeyBackend(Enum):
    Software = "software"

    @classmethod
    def from_key_backend(cls, backend: str) -> Optional["KeyBackend"]:
        """Get KeyBackend instance from the method identifier."""
        for cmp_mth in KeyBackend:
            if cmp_mth.value == backend:
                return cmp_mth

        return None

    def __str__(self):
        return self.value


class SeedMethod(Enum):
    BlsKeyGen = "bls_keygen"

    @classmethod
    def from_seed_method(cls, method: str) -> Optional["SeedMethod"]:
        """Get SeedMethod instance from the method identifier."""
        for cmp_mth in SeedMethod:
            if cmp_mth.value == method:
                return cmp_mth

        return None


class EntryOperation(Enum):
    INSERT = 0
    REPLACE = 1
    REMOVE = 2
