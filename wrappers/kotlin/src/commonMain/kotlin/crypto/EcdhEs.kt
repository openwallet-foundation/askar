package askar.crypto

import askar.Askar
import askar.enums.KeyAlgs

class EcdhEs(private val algId: String, private val apu: String, private val apv: String) {


    fun deriveKey(
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        receive: Boolean,
    ): Key {
        return Key(
            Askar.cryptoBox.keyDeriveEcdhes(
                algId,
                receive,
                apv,
                apu,
                encAlg,
                ephemeralKey.handle(),
                recipientKey.handle(),
            )
        )
    }

    fun encryptDirect(
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        message: String,
        nonce: ByteArray? = null,
        aad: String? = null,
    ): askar.EncryptedBuffer {
        val derived = this.deriveKey(encAlg, ephemeralKey, recipientKey, false)
        val encryptedBuffer = derived.aeadEncrypt(message, aad = aad?: "", nonce = nonce?: ByteArray(0))
        derived.handle().free()
        return encryptedBuffer
    }

    fun encryptDirect(
        encAlg: KeyAlgs,
        ephemeralKey: Jwk,
        recipientKey: Jwk,
        message: String,
        nonce: ByteArray? = null,
        aad: String? = null,
    ): askar.EncryptedBuffer {
        val derived = this.deriveKey(encAlg, Key.fromJwk(ephemeralKey), Key.fromJwk(recipientKey), false)
        val encryptedBuffer = derived.aeadEncrypt(message, aad = aad?: "", nonce = nonce?: ByteArray(1))
        derived.handle().free()
        return encryptedBuffer
    }

    fun decryptDirect(
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        cipherText: ByteArray,
        nonce: ByteArray,
        aad: String? = null,
        tag: ByteArray,
    ): ByteArray {
        val derived = this.deriveKey(encAlg, ephemeralKey, recipientKey, false)
        val encryptedBuffer = derived.aeadDecrypt(cipherText, aad = aad?: "", tag = tag, nonce = nonce)
        derived.handle().free()
        return encryptedBuffer
    }

    fun decryptDirect(
        encAlg: KeyAlgs,
        ephemeralKey: Jwk,
        recipientKey: Jwk,
        cipherText: ByteArray,
        nonce: ByteArray,
        aad: String? = null,
        tag: ByteArray,
    ): ByteArray {
        val derived = this.deriveKey(encAlg, Key.fromJwk(ephemeralKey), Key.fromJwk(recipientKey),  false)
        val encryptedBuffer = derived.aeadDecrypt(cipherText, aad = aad?: "", tag = tag, nonce = nonce)
        derived.handle().free()
        return encryptedBuffer
    }

    fun senderWrapKey(
        wrapAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        cek: Key,
    ): askar.EncryptedBuffer {
        val derived = this.deriveKey(wrapAlg, ephemeralKey, recipientKey, false)
        val encryptedBuffer = derived.wrapKey(cek)
        derived.handle().free()
        return encryptedBuffer
    }

    fun senderWrapKey(
        wrapAlg: KeyAlgs,
        ephemeralKey: Jwk,
        recipientKey: Jwk,
        cek: Key,
    ): askar.EncryptedBuffer {
        val derived = this.deriveKey(wrapAlg, Key.fromJwk(ephemeralKey), Key.fromJwk(recipientKey), false)
        val encryptedBuffer = derived.wrapKey(cek)
        derived.handle().free()
        return encryptedBuffer
    }

    fun receiverUnwrapKey(
        wrapAlg: KeyAlgs,
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        cipherText: ByteArray,
        nonce: ByteArray = byteArrayOf(),
        tag: String = "",
    ): Key {
        val derived = this.deriveKey(wrapAlg, ephemeralKey, recipientKey,true)
        val encryptedBuffer = derived.unwrapKey(encAlg, tag, cipherText, nonce)
        derived.handle().free()
        return encryptedBuffer
    }

    fun receiverUnwrapKey(
        wrapAlg: KeyAlgs,
        encAlg: KeyAlgs,
        ephemeralKey: Jwk,
        recipientKey: Jwk,
        cipherText: ByteArray,
        nonce: ByteArray = byteArrayOf(),
        tag: String = "",
    ): Key {
        val derived = this.deriveKey(wrapAlg, Key.fromJwk(ephemeralKey), Key.fromJwk(recipientKey),true)
        val encryptedBuffer = derived.unwrapKey(encAlg, tag, cipherText, nonce)
        derived.handle().free()
        return encryptedBuffer
    }

}