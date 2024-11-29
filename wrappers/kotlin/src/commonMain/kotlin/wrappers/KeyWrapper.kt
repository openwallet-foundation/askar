package askar.wrappers

import aries_askar.*
import askar.Askar
import askar.Askar.Companion.byteArrayToByteBuffer
import askar.Askar.Companion.secretBufferToByteArray
import askar.Askar.Companion.secretBufferToString
import askar.Askar.Companion.stringToByteBuffer
import askar.crypto.Jwk
import askar.enums.KeyAlgs
import askar.enums.KeyMethod
import askar.enums.SigAlgs
import kotlinx.cinterop.*
import kotlinx.serialization.json.Json
import platform.posix.uint8_tVar
import kotlinx.serialization.encodeToString
import platform.posix.int8_t
import platform.posix.int8_tVar

class KeyWrapper {

    fun keyGenerate(algorithm: KeyAlgs, ephemeral: Boolean): askar.crypto.LocalKeyHandleKot {
        val bool = if (ephemeral) 1 else 0
        val out = nativeHeap.alloc<LocalKeyHandle>()
        val errorCode = askar_key_generate(algorithm.alg, bool.toByte(), out.ptr)
        Askar.assertNoError(errorCode)
        return askar.crypto.LocalKeyHandleKot(out)
    }

    fun keyFromSeed(algorithm: KeyAlgs, seed: String, method: KeyMethod): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val cString = stringToByteBuffer(seed, this)
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_from_seed(algorithm.alg, cString, method.method, out.ptr)
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }

    fun keyFromSecretBytes(algorithm: KeyAlgs, secretString: ByteArray): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val buffer = byteArrayToByteBuffer(secretString, this)
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_from_secret_bytes(algorithm.alg, buffer, out.ptr)
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }

    fun keyFromPublicBytes(algorithm: KeyAlgs, publicBytes: ByteArray): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val buffer = byteArrayToByteBuffer(publicBytes, this)
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_from_public_bytes(algorithm.alg, buffer, out.ptr)
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }

    fun keyFromJwk(jwk: Jwk): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val buffer = stringToByteBuffer(jwk.toString(), this)
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_from_jwk(buffer, out.ptr)
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }

    fun keyConvert(handle: LocalKeyHandle, algorithm: KeyAlgs): askar.crypto.LocalKeyHandleKot {
        val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
        val out = nativeHeap.alloc<LocalKeyHandle>()
        val errorCode = askar_key_convert(cHandle, algorithm.alg, out.ptr)
        Askar.assertNoError(errorCode)
        return askar.crypto.LocalKeyHandleKot(out)
    }

    fun keyFromKeyExchange(
        sHandle: LocalKeyHandle,
        pHandle: LocalKeyHandle,
        algorithm: KeyAlgs
    ): askar.crypto.LocalKeyHandleKot {
        val scHandle = cValue<LocalKeyHandle> {
                _0 = sHandle._0
            }
        val pcHandle = cValue<LocalKeyHandle> {
                _0 = pHandle._0
            }
        val out = nativeHeap.alloc<LocalKeyHandle>()
        val errorCode = askar_key_from_key_exchange(algorithm.alg, scHandle, pcHandle, out.ptr)
        Askar.assertNoError(errorCode)
        return askar.crypto.LocalKeyHandleKot(out)
    }

    fun keyGetAlgorithm(handle: LocalKeyHandle): String {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_key_get_algorithm(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value!!.toKString()
        }
    }

    fun keyGetEphemeral(handle: LocalKeyHandle): int8_t {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<int8_tVar>()
            val errorCode = askar_key_get_ephemeral(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value
        }
    }

    fun keyGetPublicBytes(handle: LocalKeyHandle): ByteArray {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_get_public_bytes(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keyGetSecretBytes(handle: LocalKeyHandle): ByteArray {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_get_secret_bytes(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }


    fun keyGetJwkPublic(handle: LocalKeyHandle, algorithm: KeyAlgs): String {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_key_get_jwk_public(cHandle, algorithm.alg, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value!!.toKString()
        }
    }

    fun keyGetJwkSecret(handle: LocalKeyHandle): String {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_get_jwk_secret(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToString(out)
        }
    }

    fun keyGetJwkThumbprint(handle: LocalKeyHandle, algorithm: KeyAlgs): String {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_key_get_jwk_thumbprint(cHandle, algorithm.alg, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value!!.toKString()
        }
    }

    fun keyGetAeadParams(handle: LocalKeyHandle): askar.AeadParams {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<AeadParams>()
            val errorCode = askar_key_aead_get_params(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return askar.AeadParams(out.nonce_length, out.tag_length)
        }
    }

    fun keyAeadRandomNonce(handle: LocalKeyHandle): ByteArray {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_aead_random_nonce(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keyAeadEncrypt(handle: LocalKeyHandle, message: String, nonce: ByteArray, aad: String): askar.EncryptedBuffer {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val messageBuf = stringToByteBuffer(message, this)
            val aadBuf = stringToByteBuffer(aad, this)
            val nonceBuf = byteArrayToByteBuffer(nonce, this)
            val out = alloc<EncryptedBuffer>()
            val errorCode = askar_key_aead_encrypt(cHandle, messageBuf, nonceBuf, aadBuf, out.ptr)
            Askar.assertNoError(errorCode)
            val buf = secretBufferToByteArray(out.buffer)
            return askar.EncryptedBuffer(buf, out.tag_pos.toInt(), out.nonce_pos.toInt())
        }
    }

    fun keyAeadEncrypt(handle: LocalKeyHandle, message: ByteArray, nonce: ByteArray, aad: ByteArray): askar.EncryptedBuffer {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val messageBuf = byteArrayToByteBuffer(message, this)
            val aadBuf = byteArrayToByteBuffer(aad, this)
            val nonceBuf = byteArrayToByteBuffer(nonce, this)
            val out = alloc<EncryptedBuffer>()
            val errorCode = askar_key_aead_encrypt(cHandle, messageBuf, nonceBuf, aadBuf, out.ptr)
            Askar.assertNoError(errorCode)
            val buf = secretBufferToByteArray(out.buffer)
            return askar.EncryptedBuffer(buf, out.tag_pos.toInt(), out.nonce_pos.toInt())
        }
    }

    fun keyAeadDecrypt(
        handle: LocalKeyHandle,
        cipherText: ByteArray,
        nonce: ByteArray,
        tag: ByteArray,
        aad: String,
    ): ByteArray {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = this.alloc<SecretBuffer>()
            val cipherBuf = byteArrayToByteBuffer(cipherText, this)
            val nonceBuf = byteArrayToByteBuffer(nonce, this)
            val tagBuf = byteArrayToByteBuffer(tag, this)
            val aadBuf = stringToByteBuffer(aad, this)
            val errorCode = askar_key_aead_decrypt(cHandle, cipherBuf, nonceBuf, tagBuf, aadBuf, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keySignMessage(handle: LocalKeyHandle, message: String, sigType: SigAlgs?): ByteArray {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_sign_message(cHandle, stringToByteBuffer(message, this), sigType?.alg, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keySignMessage(handle: LocalKeyHandle, message: ByteArray, sigType: SigAlgs?): ByteArray {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_key_sign_message(cHandle, byteArrayToByteBuffer(message, this), sigType?.alg, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToByteArray(out)
        }
    }

    fun keyVerifySignature(handle: LocalKeyHandle, message: String, signature: ByteArray, sigType: SigAlgs?): int8_t {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<int8_tVar>()
            val errorCode = askar_key_verify_signature(
                cHandle,
                stringToByteBuffer(message, this),
                byteArrayToByteBuffer(signature, this),
                sigType?.alg,
                out.ptr
            )
            Askar.assertNoError(errorCode)
            return out.value
        }
    }

    fun keyVerifySignature(handle: LocalKeyHandle, message: ByteArray, signature: ByteArray, sigType: SigAlgs?): int8_t {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = alloc<int8_tVar>()
            val errorCode = askar_key_verify_signature(
                cHandle,
                byteArrayToByteBuffer(message, this),
                byteArrayToByteBuffer(signature, this),
                sigType?.alg,
                out.ptr
            )
            Askar.assertNoError(errorCode)
            return out.value
        }
    }

    fun keyWrapKey(handle: LocalKeyHandle, other: LocalKeyHandle, nonce: String): askar.EncryptedBuffer {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val cOther = cValue<LocalKeyHandle> {
                _0 = other._0
            }
            val out = alloc<EncryptedBuffer>()
            val errorCode = askar_key_wrap_key(cHandle, cOther, stringToByteBuffer(nonce, this), out.ptr)
            Askar.assertNoError(errorCode)
            val buf = secretBufferToByteArray(out.buffer)
            return askar.EncryptedBuffer(buf, out.tag_pos.toInt(), out.nonce_pos.toInt())
        }
    }

    fun keyUnwrapKey(
        handle: LocalKeyHandle,
        algorithm: KeyAlgs,
        cipherText: ByteArray,
        nonce: ByteArray,
        tag: String
    ): askar.crypto.LocalKeyHandleKot {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_unwrap_key(
                cHandle,
                algorithm.alg,
                byteArrayToByteBuffer(cipherText, this),
                byteArrayToByteBuffer(nonce, this),
                stringToByteBuffer(tag, this),
                out.ptr
            )
            Askar.assertNoError(errorCode)
            return askar.crypto.LocalKeyHandleKot(out)
        }
    }

    fun keyFree(handle: LocalKeyHandle) {
        memScoped {
            val cHandle = cValue<LocalKeyHandle> {
                _0 = handle._0
            }
            askar_key_free(cHandle)
        }
    }

}