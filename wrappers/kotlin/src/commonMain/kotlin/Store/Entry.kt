package askar.Store

import askar.crypto.EntryListHandle
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/***
 * @param category the string name of the category
 * @param name the string name of the entry
 * @param value the value passed in when the entry was created
 * @param tags a json formatted string of tags
 */
@Serializable
class EntryObject(val category: String, val name: String, val value: String, val tags: String) {

    override fun toString(): String {
        val temp = buildJsonObject {
            put("category", category)
            put("name", name)
            put("value", value)
            val tagsJson = Json.decodeFromString<JsonElement>(tags)
            put("tags", tagsJson)
        }
        return temp.toString()
    }

    override fun equals(other: Any?): Boolean {
        if(other == null) return false
        val o = other as EntryObject
        val tags = Json.decodeFromString<JsonObject>(this.tags)
        val otherTags = Json.decodeFromString<JsonObject>(o.tags)
        return o.category == this.category && o.name == this.name && o.value == this.value && tags == otherTags
    }

}
class Entry (private val list: EntryListHandle, private val pos: Int) {

    fun category(): String {
        return this.list.getCategory(this.pos)
    }

    fun name(): String {
        return this.list.getName(this.pos)
    }

    fun value(): String {
        return this.list.getValue(this.pos)
    }

    //Revisit if needed later
//    private fun rawValue(): String {
//        return this.list.getValue(this.pos)
//    }

    fun tags(): String {
        return list.getTags(pos) ?: "{}"
    }

    fun toJson(): EntryObject {
        val entry = EntryObject(category(), name(), tags = tags(), value = value())
       return entry
    }

}