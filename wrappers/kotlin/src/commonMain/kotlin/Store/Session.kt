package askar.Store

import askar.Askar
import askar.Askar.Companion.mapToJsonObject
import askar.crypto.Key
import askar.crypto.SessionHandle
import askar.enums.EntryOperation
import askar.enums.KeyAlgs
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.memScoped
import kotlinx.serialization.json.*

@OptIn(UnsafeNumber::class)
class Session(private var handle: SessionHandle?, private val isTxn: Boolean) {

    fun isTransaction(): Boolean {
        return this.isTxn
    }

    fun handle(): SessionHandle? {
        return this.handle
    }

    suspend fun count(category: String, tagFilter: String): Long {
        if (this.handle == null) throw Error("Cannot get count of closed session")
        val handle = this.handle
        var count = Askar.session.sessionCount(handle!!.handle, category, tagFilter)
        return count
    }

    suspend fun fetch(
        category: String,
        name: String,
        forUpdate: Boolean = false,
    ): EntryObject? {
        if (this.handle == null) throw Error("Cannot fetch from a close session")
        val h = Askar.session.sessionFetch(handle!!.handle, category, name, forUpdate) ?: return null
        val entry = Entry(h, 0)
        return entry.toJson()
    }

    suspend fun fetchAll(
        category: String,
        tagFilter: String = "{}",
        forUpdate: Boolean = false,
        limit: Long = -1L,
    ): ArrayList<EntryObject> {
        if (this.handle == null) throw Error("Cannot fetch from a closed session")
        val handle =
            Askar.session.fetchAll(handle!!.handle, category, tagFilter, limit, forUpdate)
                ?: return arrayListOf()
        val entryList = EntryList(handle)
        return entryList.toArray()
    }

    suspend fun insert(
        category: String,
        name: String,
        expiryMs: Long = -1,
        tags: String = "{}",
        value: String
    ): Boolean {
        if (this.handle == null) throw Error("Cannot insert into a closed session")
        val code = Askar.session.sessionUpdate(
            handle!!.handle,
            category,
            name,
            expiryMs,
            tags,
            value,
            EntryOperation.Insert
        )
        return code == 0L
    }

    suspend fun replace(
        category: String,
        name: String,
        expiryMs: Long = -1,
        tags: String = "{}",
        value: String
    ): Boolean {
        if (this.handle == null) throw Error("Cannot replace in a closed session")
        val code =
            Askar.session.sessionUpdate(
                handle!!.handle,
                category,
                name,
                expiryMs,
                tags,
                value,
                EntryOperation.Replace
            )
        return code == 0L
    }

    suspend fun remove(category: String, name: String): Boolean {
        if (this.handle == null) throw Error("Cannot remove from a closed session")
        val code =
            Askar.session.sessionUpdate(
                handle!!.handle,
                category,
                name,
                0,
                "{}",
                "",
                EntryOperation.Remove
            )
        return code == 0L
    }

    suspend fun removeAll(category: String, tagFilter: String = "{}"): Boolean {
        if (this.handle == null) throw Error("Cannot remove from a closed session")
        val code = Askar.session.sessionRemoveAll(handle!!.handle, category, tagFilter)
        return code == 0L
    }

    suspend fun insertKey(
        name: String,
        key: Key,
        expiryMs: Long = -1,
        metadata: String? = null,
        tags: String = "{}"
    ): Boolean {
        if (this.handle == null) throw Error("Cannot insert a key with a closed session")
        val code = Askar.session.sessionInsertKey(handle!!.handle, name, key, metadata, tags, expiryMs)
        return code == 0L
    }


    suspend fun fetchKey(name: String, forUpdate: Boolean = false): KeyEntryObject? {
        if (this.handle == null) throw Error("Cannot fetch key from closed session")
        val handle = Askar.session.sessionFetchKey(handle!!.handle, name, forUpdate) ?: return null
        val keyEntryList = KeyEntryList(handle)

        return keyEntryList.getEntryByIndex(0).toJson()
    }

    suspend fun fetchAllKeys(
        algorithm: KeyAlgs? = null,
        thumbprint: String? = null,
        tagFilter: String? = null,
        limit: Long = -1,
        forUpdate: Boolean = false,
    ): ArrayList<KeyEntryObject> {
        if (this.handle == null) throw Error("Cannot fetch keys from a closed session")
        val handle = Askar.session.sessionFetchAllKeys(
            handle!!.handle,
            algorithm,
            thumbprint,
            tagFilter,
            limit,
            forUpdate,
        ) ?: return ArrayList()
        val keyEntryList = KeyEntryList(handle)
        return keyEntryList.toArray()
    }

    suspend fun updateKey(
        name: String,
        metadata: String? = null,
        tags: String = "{}",
        expiryMs: Long = -1
    ): Boolean {
        if (this.handle == null) throw Error("Cannot update key from a closed session")
        val code = Askar.session.sessionUpdateKey(handle!!.handle, name, metadata, tags, expiryMs)
        return code == 0L
    }

    suspend fun removeKey(name: String): Boolean {
        if (this.handle == null) throw Error("Cannot remove key from a closed session")
        val code = Askar.session.sessionRemoveKey(handle!!.handle, name)
        return code == 0L
    }

    /**
     * @Note also closes the session
     */
    suspend fun commit(): Boolean {
        if (!this.isTxn) throw Error("Session is not a transaction")
        if (this.handle == null) throw Error("Cannot commit a closed session")
        val code = handle!!.close(true)
        this.handle = null
        return code == 0L
    }

    suspend fun rollback(): Boolean {
        if (!this.isTxn) throw Error("Session is not a transaction")
        if (this.handle == null) throw Error("Cannot rollback a closed session")
        val code = handle!!.close(false)
        this.handle = null
        return code == 0L
    }

    suspend fun close(): Boolean {
        if (this.handle == null) throw Error("Cannot close a closed session")
        val code = handle!!.close(false)
        this.handle = null
        return code == 0L
    }


}