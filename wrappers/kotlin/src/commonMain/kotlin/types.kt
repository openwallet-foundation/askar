@file:OptIn(ExperimentalUnsignedTypes::class, ExperimentalUnsignedTypes::class, ExperimentalUnsignedTypes::class)

package askar

import askar.crypto.Jwk
import askar.crypto.Key
import askar.enums.KeyAlgs
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json


class AeadParams(val nonceLength: Int, val tagsLength: Int)

class EncryptedBuffer(
    val buffer: ByteArray,
    val tagPos: Int,
    val noncePos: Int
) {


    fun cipherTextWithTag(): ByteArray {
        val p = this.noncePos
        return buffer.slice(0 until p).toByteArray()
    }

    fun cipherText(): ByteArray {
        val p = tagPos
        return buffer.slice(0 until  p).toByteArray()
    }

    fun nonce(): ByteArray {
        val p = noncePos
        return buffer.slice(p until buffer.size).toByteArray()
    }

    fun tag(): ByteArray {
        val p1 = tagPos
        val p2 = noncePos
        return buffer.slice(p1 until p2).toByteArray()
    }

}
@Serializable
class ProtectedJson(val alg: String, val enc: String, val apu: String, val apv: String, val epk: Jwk){

    constructor(alg: String, enc: KeyAlgs, apu: String, apv: String, epk: Jwk) : this(alg, enc.alg, apu, apv, epk)

    override fun toString(): String {
        return Json.encodeToString(this)
    }

}

