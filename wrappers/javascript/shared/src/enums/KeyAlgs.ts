import { AriesAskarError } from '../error'

export enum KeyAlgs {
  AesA128Gcm = 'a128gcm',
  AesA256Gcm = 'a256gcm',
  AesA128CbcHs256 = 'a128cbchs256',
  AesA256CbcHs512 = 'a256cbchs512',
  AesA128Kw = 'a128kw',
  AesA256Kw = 'a256kw',
  Bls12381G1 = 'bls12381g1',
  Bls12381G2 = 'bls12381g2',
  Chacha20C20P = 'c20p',
  Chacha20XC20P = 'xc20p',
  Ed25519 = 'ed25519',
  X25519 = 'x25519',
  EcSecp256k1 = 'k256',
  EcSecp256r1 = 'p256',
}

export const getKeyAlgs = (alg: string): KeyAlgs => {
  const keyAlg = Object.entries(KeyAlgs).find(([, value]) => value === alg)
  if (keyAlg) return keyAlg[1]

  throw new AriesAskarError({ code: 100, message: `Algorithm: ${alg} is not supported!` })
}