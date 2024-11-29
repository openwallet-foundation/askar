package askar.wrappers

import aries_askar.*
import askar.Askar
import askar.Askar.Companion.byteArrayToByteBuffer
import askar.Askar.Companion.secretBufferToByteArray
import askar.Askar.Companion.secretBufferToString
import askar.Askar.Companion.stringToByteBuffer
import askar.enums.KeyAlgs
import kotlinx.cinterop.*


class CryptoBoxWrapper {

    fun keyCryptoBoxRandomNonce(): ByteArray {
        memScoped {
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_crypto_box_random_nonce(out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keyCryptoBox(
        recipientKey: askar.crypto.LocalKeyHandleKot,
        senderKey: askar.crypto.LocalKeyHandleKot,
        message: String,
        nonce: ByteArray
    ): ByteArray {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val sk = cValue<LocalKeyHandle> {
                _0 = senderKey.handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode =
                askar_key_crypto_box(rk, sk, stringToByteBuffer(message, this), byteArrayToByteBuffer(nonce, this), out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keyCryptoBox(
        recipientKey: askar.crypto.LocalKeyHandleKot,
        senderKey: askar.crypto.LocalKeyHandleKot,
        message: ByteArray,
        nonce: ByteArray
    ): ByteArray {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val sk = cValue<LocalKeyHandle> {
                _0 = senderKey.handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode =
                askar_key_crypto_box(rk, sk, byteArrayToByteBuffer(message, this), byteArrayToByteBuffer(nonce, this), out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun cryptoBoxOpen(
        recipientKey: askar.crypto.LocalKeyHandleKot,
        senderKey: askar.crypto.LocalKeyHandleKot,
        message: ByteArray,
        nonce: ByteArray
    ): ByteArray {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val sk = cValue<LocalKeyHandle> {
                _0 = senderKey.handle._0
            }
            val out = alloc<SecretBuffer>()

            val errorCode =
                askar_key_crypto_box_open(rk, sk, byteArrayToByteBuffer(message, this), byteArrayToByteBuffer(nonce, this), out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun cryptoBoxSeal(recipientKey: askar.crypto.LocalKeyHandleKot, message: String): ByteArray {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_crypto_box_seal(rk, stringToByteBuffer(message, this), out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun cryptoBoxSeal(recipientKey: askar.crypto.LocalKeyHandleKot, message: ByteArray): ByteArray {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_crypto_box_seal(rk, byteArrayToByteBuffer(message, this), out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun cryptoBoxSealOpen(recipientKey: askar.crypto.LocalKeyHandleKot, cipherText: ByteArray): ByteArray {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_crypto_box_seal_open(rk, byteArrayToByteBuffer(cipherText, this), out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keyDeriveEcdh1pu(
        algId: String,
        receive: Boolean,
        apv: String,
        apu: String,
        encAlg: KeyAlgs,
        ephemeralKey: askar.crypto.LocalKeyHandleKot,
        recipientKey: askar.crypto.LocalKeyHandleKot,
        senderKey: askar.crypto.LocalKeyHandleKot,
        ccTag: String
    ): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val sk = cValue<LocalKeyHandle> {
                _0 = senderKey.handle._0
            }
            val ek = cValue<LocalKeyHandle> {
                _0 = ephemeralKey.handle._0
            }
            val bool = receive.toByte()
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_derive_ecdh_1pu(
                encAlg.alg, ek, sk, rk, stringToByteBuffer(algId, this), stringToByteBuffer(apu, this), stringToByteBuffer(apv, this),
                stringToByteBuffer(ccTag, this), bool, out.ptr
            )
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }

    fun keyDeriveEcdh1pu(
        algId: String,
        receive: Boolean,
        apv: String,
        apu: String,
        encAlg: KeyAlgs,
        ephemeralKey: askar.crypto.LocalKeyHandleKot,
        recipientKey: askar.crypto.LocalKeyHandleKot,
        senderKey: askar.crypto.LocalKeyHandleKot,
        ccTag: ByteArray
    ): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val sk = cValue<LocalKeyHandle> {
                _0 = senderKey.handle._0
            }
            val ek = cValue<LocalKeyHandle> {
                _0 = ephemeralKey.handle._0
            }
            val bool = receive.toByte()
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_derive_ecdh_1pu(
                encAlg.alg, ek, sk, rk, stringToByteBuffer(algId, this), stringToByteBuffer(apu, this), stringToByteBuffer(apv, this),
                byteArrayToByteBuffer(ccTag, this), bool, out.ptr
            )
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }

    fun keyDeriveEcdhes(
        algId: String,
        receive: Boolean,
        apv: String,
        apu: String,
        encAlg: KeyAlgs,
        ephemeralKey: askar.crypto.LocalKeyHandleKot,
        recipientKey: askar.crypto.LocalKeyHandleKot,
    ): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val rk = cValue<LocalKeyHandle> {
                _0 = recipientKey.handle._0
            }
            val ek = cValue<LocalKeyHandle> {
                _0 = ephemeralKey.handle._0
            }
            val bool = receive.toByte()
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_derive_ecdh_es(
                encAlg.alg, ek, rk, stringToByteBuffer(algId, this), stringToByteBuffer(apu, this), stringToByteBuffer(apv, this),
                bool, out.ptr
            )
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }
}