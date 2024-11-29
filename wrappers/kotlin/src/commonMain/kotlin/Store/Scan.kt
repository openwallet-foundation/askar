package askar.Store

import aries_askar.askar_get_current_error
import askar.Askar
import askar.crypto.EntryListHandle
import askar.crypto.ScanHandle
import kotlinx.cinterop.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject

@OptIn(UnsafeNumber::class)
class Scan(
    private val profile: String? = null,
    private val category: String,
    private val tagFilter: JsonObject = buildJsonObject {},
    private val offset: Int = 0,
    private val limit: Int = -1,
    private val store: Store
) {
    private var handle: ScanHandle? = null
    private var listHandle: EntryListHandle? = null

    fun handle(): ScanHandle? {
        return this.handle
    }

    suspend fun forEach(cb: (row: Entry, index: Int) -> Unit) {
        memScoped {
            if (handle == null) {
                handle = Askar.scan.scanStart(store.handle().handle, limit, offset, tagFilter, profile, category)
            }
            try {
                var recordCount = 0
                while (limit == -1 || recordCount < limit) {
                    val list = Askar.scan.scanNext(handle!!.handle, this) ?: break
                    listHandle = list

                    val entryList = EntryList(list)

                    recordCount += entryList.length()
                    for (i in 0 until entryList.length()) {
                        val entry = entryList.getEntryByIndex(i)
                        cb(entry, i)
                    }
                }

            } finally {
                Askar.scan.free(handle!!.handle)
            }
        }

    }

    suspend fun fetchAll(): ArrayList<EntryObject> {
        val rows = ArrayList<EntryObject>()
        forEach { row: Entry, _ -> rows.add(row.toJson()) }
        return rows
    }
}