@file:OptIn(
    ExperimentalEncodingApi::class
)

package tech.indicio.holdr

import askar.ProtectedJson
import askar.crypto.Ecdh1PU
import askar.crypto.EcdhEs
import askar.crypto.Jwk
import askar.crypto.Key
import askar.enums.KeyAlgs
import kotlinx.cinterop.toKString
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals

class JoseEcdh {

    fun base64Url(str: String): String {
        return Base64.UrlSafe.encode(str.encodeToByteArray())
    }

    @Test
    fun ecdhEsDirect() {
        val bobKey = Key.generate(KeyAlgs.EcSecp256r1)
        //val bobJwk = bobKey.jwkPublic()
        val ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1)
        val ephemeralJwk = ephemeralKey.jwkPublic()
        val message = "Hello there"
        val alg = "ECDH-ES"
        val apu = "Alice"
        val apv = "Bob"
        val encAlg = KeyAlgs.AesA256Gcm
        val json = ProtectedJson(alg, KeyAlgs.AesA256Gcm, "Alice", "Bob", ephemeralJwk)

        val b64 = Base64.UrlSafe.encode(json.toString().encodeToByteArray())

        val encryptedMessage =
            EcdhEs(encAlg.alg, apu, apv).encryptDirect(encAlg, ephemeralKey, bobKey, message, aad = b64)
        val nonce = encryptedMessage.nonce()
        val tags = encryptedMessage.tag()
        val cipherText = encryptedMessage.cipherText()

        val messageReceived = EcdhEs(encAlg.alg, apu, apv).decryptDirect(
            encAlg,
            ephemeralKey,
            bobKey,
            cipherText,
            nonce,
            b64,
            tags
        )
        assertEquals(message, messageReceived.toKString())
        ephemeralKey.handle().free()
        bobKey.handle().free()
    }

    @Test
    fun ecdhEsWrapped() {
        val bobKey = Key.generate(KeyAlgs.X25519)
        val bobJwk = bobKey.jwkPublic()
        val ephemeralKey = Key.generate(KeyAlgs.X25519)
        val ephemeralJwk = ephemeralKey.jwkPublic()
        val message = "Hello there"
        val alg = "ECDH-ES+A128KW"
        val enc = "A256GCM"
        val apu = "Alice"
        val apv = "bob"

        val json = ProtectedJson(alg, enc, apu, apv, ephemeralJwk)

        val b64 = Base64.UrlSafe.encode(json.toString().encodeToByteArray())

        val cek = Key.generate(KeyAlgs.AesA256Gcm)

        val encryptedMessage = cek.aeadEncrypt(message, aad = b64)
        val nonce = encryptedMessage.nonce()
        val tags = encryptedMessage.tag()
        val cipherText = encryptedMessage.cipherText()

        val encryptedKey = EcdhEs(alg, apu, apv).senderWrapKey(
            KeyAlgs.AesA128Kw,
            ephemeralKey,
            Key.fromJwk(bobJwk),
            cek,
        ).cipherText()

        val cekReceiver = EcdhEs(alg, apu, apv).receiverUnwrapKey(
            KeyAlgs.AesA128Kw,
            KeyAlgs.AesA256Gcm,
            Key.fromJwk(ephemeralJwk),
            bobKey,
            cipherText = encryptedKey
        )

        val messageReceived = cekReceiver.aeadDecrypt(cipherText, nonce, tags, b64)

        assertEquals(message, messageReceived.toKString())
        ephemeralKey.handle().free()
        bobKey.handle().free()
        cek.handle().free()
        cekReceiver.handle().free()
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun ecdh1puDirect() {
        val aliceKey = Key.generate(KeyAlgs.EcSecp256r1)
        val aliceJwk = aliceKey.jwkSecret()
        val bobKey = Key.generate(KeyAlgs.EcSecp256r1)
        val bobJwk = bobKey.jwkPublic()
        val ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1)
        val ephemeralJwk = ephemeralKey.jwkPublic()
        val message = "Hello there"
        val alg = "ECDH-1PU"
        val enc = KeyAlgs.AesA256Gcm
        val apu = "Alice"
        val apv = "Bob"
        val protectedJson = ProtectedJson(
            alg,
            enc,
            base64Url(apu),
            base64Url(apv),
            ephemeralJwk
        )
        val protectedString = protectedJson.toString()
        val protectedB64 = Base64.UrlSafe.encode(protectedString.encodeToByteArray())

        val encryptedMessage = Ecdh1PU(
            enc.alg,
            apu,
            apv
        ).encryptDirect(
            KeyAlgs.AesA256Gcm,
            ephemeralKey,
            Key.fromJwk(bobJwk),
            senderKey = aliceKey,
            message = message,
            aad = protectedB64,
        )

        val nonce = encryptedMessage.nonce()
        val tag = encryptedMessage.tag()
        val ciphertext = encryptedMessage.cipherText()

        val messageReceived = Ecdh1PU(
            enc.alg,
            apu,
            apv,
        ).decryptDirect(
            KeyAlgs.AesA256Gcm,
            ephemeralKey,
            bobKey,
            Key.fromJwk(aliceJwk),
            ciphertext,
            nonce,
            protectedB64,
            tag
        )

        assertEquals(message, messageReceived.toKString())
        aliceKey.handle().free()
        bobKey.handle().free()
        ephemeralKey.handle().free()
    }

    private fun bufferFromHex(str: String): ByteArray {
        val list = str.chunked(2)
        val arr = ByteArray(list.size) {
            list[it].toUInt(16).toByte()
        }
        return arr
    }

    /**
     *
     * These tests have been implemented as a copy from the python wapper.
     * The test vectores have been taken from:
     * https://www.ietf.org/archive/id/draft-madden-jose-ecdh-1pu-04.txt
     */
    @Test
    fun ecdh1puWrapped() {
        val ephemeral = Key.fromJwk(
            Jwk(
                "OKP",
                "X25519",
                "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
                "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"
            )
        )

        val alice = Key.fromJwk(
            Jwk(
                "OKP",
                "X25519",
                "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
                "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU",
            )
        )

        val bob = Key.fromJwk(
            Jwk(
                "OKP",
                "X25519",
                "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            )
        )

        val alg = "ECDH-1PU+A128KW"
        val apu = "Alice"
        val apv = "Bob and Charlie"
        val base64urlApu = base64Url(apu)
        val base64urlApv = base64Url(apv)

        assertEquals("QWxpY2U=", base64urlApu)
        assertEquals("Qm9iIGFuZCBDaGFybGll", base64urlApv)

        val protectedJson = ProtectedJson(
            alg,
            "A256CBC-HS512",
            "QWxpY2U",
            "Qm9iIGFuZCBDaGFybGll",
            Jwk("OKP", "X25519", "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"),
        )

        val b64 = base64Url(protectedJson.toString())

        val str =
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0"

        val arr = bufferFromHex(str)

        val cek = Key.fromSecretBytes(KeyAlgs.AesA256CbcHs512, arr)

        val iv = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        val message = "Three is a magic number."

        val enc = cek.aeadEncrypt(message, iv, b64)

        val tags = enc.tag()
        val ciphertext = enc.cipherText()

        assertEquals("Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw=", Base64.UrlSafe.encode(ciphertext))
        assertEquals("HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ=", Base64.UrlSafe.encode(tags))

        val derived = Ecdh1PU(
            apv = apv,
            apu = apu,
            algId = alg
        ).deriveKey(
            encAlg = KeyAlgs.AesA128Kw,
            recipientKey = bob,
            senderKey = alice,
            ccTag = tags,
            ephemeralKey = ephemeral,
            receive = false
        )

        val expectedBuf = bufferFromHex("df4c37a0668306a11e3d6b0074b5d8df")

        derived.secretBytes().forEachIndexed { index, byte ->
            assertEquals(expectedBuf[index], byte)
        }

        val encryptedKey = derived.wrapKey(cek).cipherText()

        val expectedKey = Base64.UrlSafe.decode("pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN")

        encryptedKey.forEachIndexed { index, byte ->
            assertEquals(expectedKey[index], byte)
        }

        val encryptedKey2 = Ecdh1PU(apv = apv, apu = apu, algId = alg).senderWrapKey(
            wrapAlg = KeyAlgs.AesA128Kw,
            ephemeralKey = ephemeral,
            senderKey = alice,
            recipientKey = bob,
            ccTag = tags,
            cek = cek
            )

        encryptedKey2.cipherText().forEachIndexed { index, byte ->
            assertEquals(byte, encryptedKey[index])
        }

        val derivedReciever = Ecdh1PU(apv = apv, apu = apu, algId = alg).deriveKey(
            encAlg = KeyAlgs.AesA128Kw,
            ephemeralKey = ephemeral,
            senderKey = alice,
            recipientKey = bob,
            ccTag = tags,
            receive = true
        )

        val cekReveiver = derivedReciever.unwrapKey(algorithm = KeyAlgs.AesA256CbcHs512, cipherText = encryptedKey)

        val messageReceived = cekReveiver.aeadDecrypt(cipherText = ciphertext, nonce = iv, aad = b64, tag = tags)

        assertEquals(message, messageReceived.toKString())

        val cekReceiver2 = Ecdh1PU(
            apv = apv,
            apu = apu,
            algId = alg
        ).receiverUnwrapKey(
                wrapAlg =  KeyAlgs.AesA128Kw,
                encAlg =  KeyAlgs.AesA256CbcHs512,
                ephemeralKey =  ephemeral,
                senderKey =  alice,
                recipientKey =  bob,
                cipherText = encryptedKey,
                ccTag = tags
        )

        assertEquals(cekReceiver2.jwkSecret(), cek.jwkSecret())

        cek.handle().free()
        ephemeral.handle().free()
        alice.handle().free()
        bob.handle().free()
        derived.handle().free()
    }

}