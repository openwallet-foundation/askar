package askar.crypto

import askar.Askar
import askar.enums.KeyAlgs
import askar.enums.KeyMethod
import askar.enums.SigAlgs
import askar.enums.keyAlgFromString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

class Key(private val localKeyHandle: LocalKeyHandleKot) {

    companion object {

        fun generate(algorithm: KeyAlgs, ephemeral: Boolean = false, ): Key {
            return Key(Askar.key.keyGenerate(algorithm, ephemeral))
        }

        fun fromSeed(method: KeyMethod = KeyMethod.None, algorithm: KeyAlgs, seed: String): Key {
            return Key(Askar.key.keyFromSeed(algorithm, seed, method))
        }

        fun fromSecretBytes(algorithm: KeyAlgs, secretKey: ByteArray): Key {
            return Key(Askar.key.keyFromSecretBytes(algorithm, secretKey))
        }

        fun fromPublicBytes(algorithm: KeyAlgs, publicKey: ByteArray): Key {
            return Key(Askar.key.keyFromPublicBytes(algorithm, publicKey))
        }

        fun fromJwk(jwk: Jwk): Key {
            return Key(Askar.key.keyFromJwk(jwk))
        }
    }

    fun handle(): LocalKeyHandleKot {
        return this.localKeyHandle
    }

    fun convertKey(algorithm: KeyAlgs): Key {
        return Key(Askar.key.keyConvert(this.localKeyHandle.handle, algorithm))
    }

    fun fromKeyExchange(algorithm: KeyAlgs, publicKey: Key): Key {
        return Key(Askar.key.keyFromKeyExchange(this.localKeyHandle.handle, publicKey.localKeyHandle.handle, algorithm))
    }

    fun algorithm(): KeyAlgs {
        val alg = Askar.key.keyGetAlgorithm(this.localKeyHandle.handle)
        return keyAlgFromString(alg)
    }

    fun ephemeral(): Boolean {
        val num = Askar.key.keyGetEphemeral(this.localKeyHandle.handle)
        return num.toInt() != 0
    }

    fun publicBytes(): ByteArray {
        return Askar.key.keyGetPublicBytes(this.localKeyHandle.handle)
    }

    fun secretBytes(): ByteArray {
        return Askar.key.keyGetSecretBytes(this.localKeyHandle.handle)
    }

    fun jwkPublic(): Jwk {
        return Json.decodeFromString(Askar.key.keyGetJwkPublic(this.localKeyHandle.handle, this.algorithm()))
    }

    fun jwkSecret(): Jwk {
        val buffer = Askar.key.keyGetJwkSecret(this.localKeyHandle.handle)
        return Json.decodeFromString(buffer)
    }

    fun jwkThumbprint(): String {
        return Askar.key.keyGetJwkThumbprint(this.localKeyHandle.handle, this.algorithm())
    }

    fun aeadParams(): askar.AeadParams {
        return Askar.key.keyGetAeadParams(this.localKeyHandle.handle)
    }

    fun aeadRandomNonce(): ByteArray {
        return Askar.key.keyAeadRandomNonce(this.localKeyHandle.handle)
    }

    fun aeadEncrypt(
        message: String,
        nonce: ByteArray = ByteArray(0),
        aad: String = ""
    ): askar.EncryptedBuffer {
        return Askar.key.keyAeadEncrypt(localKeyHandle.handle, message, nonce, aad)
    }

    fun aeadEncrypt(
        message: ByteArray,
        nonce: ByteArray = ByteArray(0),
        aad: ByteArray = byteArrayOf(0)
    ): askar.EncryptedBuffer {
        return Askar.key.keyAeadEncrypt(localKeyHandle.handle, message, nonce, aad)
    }

    fun aeadDecrypt(
        cipherText: ByteArray,
        nonce: ByteArray = ByteArray(0),
        tag: ByteArray = ByteArray(0),
        aad: String = ""
    ): ByteArray {
        return Askar.key.keyAeadDecrypt(localKeyHandle.handle, cipherText, nonce, tag, aad)
    }

    fun signMessage(message: String, sigType: SigAlgs? = null): ByteArray {
        return Askar.key.keySignMessage(this.localKeyHandle.handle, message, sigType)
    }

    fun signMessage(message: ByteArray, sigType: SigAlgs? = null): ByteArray {
        return Askar.key.keySignMessage(this.localKeyHandle.handle, message, sigType)
    }

    fun verifySignature(message: String, signature: ByteArray, sigType: SigAlgs? = null): Boolean {
        val num = Askar.key.keyVerifySignature(this.localKeyHandle.handle, message, signature, sigType)
        return num.toInt() != 0
    }

    fun verifySignature(message: ByteArray, signature: ByteArray, sigType: SigAlgs? = null): Boolean {
        val num = Askar.key.keyVerifySignature(this.localKeyHandle.handle, message, signature, sigType)
        return num.toInt() != 0
    }

    fun wrapKey(other: Key, nonce: String = ""): askar.EncryptedBuffer {
        return Askar.key.keyWrapKey(this.localKeyHandle.handle, other.localKeyHandle.handle, nonce)
    }

    fun unwrapKey(algorithm: KeyAlgs, tag: String = "", cipherText: ByteArray = ByteArray(0), nonce: ByteArray = byteArrayOf()): Key {
        return Key(Askar.key.keyUnwrapKey(this.localKeyHandle.handle, algorithm, cipherText, nonce, tag))
    }

}