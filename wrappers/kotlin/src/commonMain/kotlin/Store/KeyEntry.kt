package askar.Store

import askar.crypto.Key
import askar.crypto.KeyEntryListHandle

import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/***
 * @param algorithm the string name of the category
 * @param name the string name of the entry
 * @param metadata the metadata passed in when the entry was created
 * @param tags a json formatted string of tags
 */
@Serializable
class KeyEntryObject(
    val algorithm: String,
    val name: String,
    val metadata: String?,
    val tags: String,
    @Transient
    val key: Key? = null
) {

    override fun toString(): String {
        val temp = buildJsonObject {
            put("algorithm", algorithm)
            put("name", name)
            put("metadata", metadata)
            val tagsJson = Json.decodeFromString<JsonElement>(tags)
            put("tags", tagsJson)
        }

        return temp.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        val o = other as KeyEntryObject
        val tags = Json.decodeFromString<JsonObject>(this.tags)
        val otherTags = Json.decodeFromString<JsonObject>(o.tags)
        return o.algorithm == this.algorithm && o.name == this.name && tags == otherTags && o.metadata == this.metadata
    }

}

class KeyEntry(
    private val list: KeyEntryListHandle,
    private val pos: Int
) {

    fun algorithm(): String {
        return list.getAlgorithm(pos)
    }

    fun name(): String {
        return list.getName(pos)
    }

    fun metadata(): String? {
        return list.getMetadata(pos)
    }

    fun tags(): String {
        return list.getTags(pos) ?: "{}"
    }

    fun key(): Key {
        return Key(list.loadKey(pos))
    }

    fun toJson(): KeyEntryObject {
        val entry = KeyEntryObject(algorithm(), name(), metadata(), tags(), key())

        return entry
    }
}