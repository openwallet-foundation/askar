package askar.Store

import askar.Askar
import askar.crypto.EntryListHandle

class EntryList(private val handle: EntryListHandle, length: Int? = null) {
    private val length: Int

    init {
        this.length = length?: Askar.entryList.entryListCount(handle.handle)
    }

    fun handle(): EntryListHandle {
        return handle
    }

    fun length(): Int {
        return length
    }

    fun getEntryByIndex(index: Int): Entry {
        return Entry(this.handle, index)
    }

    private fun forEach(cb: (entry: Entry, index: Int) -> Any){
        for(i in 0 until this.length){
            cb(getEntryByIndex(i), i)
        }
    }

    fun find(cb: (entry: Entry, index: Int) -> Boolean): Entry? {
        for(i in 0 until this.length){
            if(cb(this.getEntryByIndex(i), i))
                return this.getEntryByIndex(i)
        }
        return null
    }

    fun toArray(): ArrayList<EntryObject> {
        val list = ArrayList<EntryObject>(this.length)
        this.forEach { entry, _ -> list.add(entry.toJson()) }
        return list
    }

}