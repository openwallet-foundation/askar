package askar.Store

import askar.Askar
import askar.crypto.KeyEntryListHandle

class KeyEntryList(private val handle: KeyEntryListHandle) {
    private val length: Int = Askar.keyEntryList.count(handle.handle)


    fun handle(): KeyEntryListHandle {
        return handle
    }

    fun length(): Int {
        return length
    }

    fun getEntryByIndex(index: Int): KeyEntry {
        return KeyEntry(handle, index)
    }

    fun forEach(cb: (entry: KeyEntry, index: Int) -> Any) {
        for(i in 0 until length) {
            cb(getEntryByIndex(i), i)
        }
    }

    fun toArray(): ArrayList<KeyEntryObject> {
        val list = ArrayList<KeyEntryObject>(length)
        forEach{ entry, _ -> list.add(entry.toJson()) }
        return list
    }


}