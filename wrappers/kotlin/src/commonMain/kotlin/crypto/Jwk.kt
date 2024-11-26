package askar.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
class Jwk(
    val kty: String,
    val crv: String? = null,
    val x: String? = null,
    val d: String? = null,
    val y: String? = null,
    val alg: String? = null,
    val k: String? = null
) {
    override fun toString(): String {
        return Json.encodeToString(this)
    }

    override fun equals(other: Any?): Boolean {
        val o = other as Jwk
        return this.toString() == o.toString()
    }
}