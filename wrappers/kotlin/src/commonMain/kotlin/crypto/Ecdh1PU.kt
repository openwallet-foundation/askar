package askar.crypto

import aries_askar.ByteBuffer
import aries_askar.EncryptedBuffer
import askar.Askar
import askar.Askar.Companion.stringToByteBuffer
import askar.enums.KeyAlgs
import kotlinx.cinterop.CValue
import kotlinx.cinterop.MemScope

class Ecdh1PU(private val algId: String, private val apu: String, private val apv: String) {


    fun deriveKey(
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        senderKey: Key,
        receive: Boolean,
        ccTag: ByteArray = byteArrayOf()
    ): Key {
        return Key(
            Askar.cryptoBox.keyDeriveEcdh1pu(
                algId,
                receive,
                apv,
                apu,
                encAlg,
                ephemeralKey.handle(),
                recipientKey.handle(),
                senderKey.handle(),
                ccTag
            )
        )
    }

    fun encryptDirect(
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        senderKey: Key,
        message: String,
        nonce: ByteArray? = null,
        aad: String? = null,
    ): askar.EncryptedBuffer {
        val derived = this.deriveKey(encAlg, ephemeralKey, recipientKey, senderKey, false, ccTag = byteArrayOf())
        val encryptedBuffer = derived.aeadEncrypt(message = message, aad = aad?: "", nonce = nonce?: ByteArray(0))
        derived.handle().free()
        return encryptedBuffer
    }

    fun decryptDirect(
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        senderKey: Key,
        cipherText: ByteArray,
        nonce: ByteArray,
        aad: String? = null,
        tag: ByteArray,
    ): ByteArray {
        val derived = this.deriveKey(encAlg, ephemeralKey, recipientKey, senderKey, false, ccTag = byteArrayOf())
        val encryptedBuffer = derived.aeadDecrypt(cipherText, aad = aad?: "", tag = tag, nonce = nonce)
        derived.handle().free()
        return encryptedBuffer
    }

    fun senderWrapKey(
        wrapAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        senderKey: Key,
        cek: Key,
        ccTag: ByteArray
    ): askar.EncryptedBuffer {
        val derived = this.deriveKey(wrapAlg, ephemeralKey, recipientKey, senderKey, false, ccTag)
        val encryptedBuffer = derived.wrapKey(cek)
        derived.handle().free()
        return encryptedBuffer
    }

    fun receiverUnwrapKey(
        wrapAlg: KeyAlgs,
        encAlg: KeyAlgs,
        ephemeralKey: Key,
        recipientKey: Key,
        senderKey: Key,
        cipherText: ByteArray,
        nonce: ByteArray = byteArrayOf(),
        tag: String = "",
        ccTag: ByteArray = byteArrayOf()
    ): Key {
        val derived = this.deriveKey(wrapAlg, ephemeralKey, recipientKey, senderKey, false, ccTag)
        val encryptedBuffer = derived.unwrapKey(encAlg, tag, cipherText, nonce)
        derived.handle().free()
        return encryptedBuffer
    }

}