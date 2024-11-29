@file:OptIn(UnsafeNumber::class)

package askar.crypto

import aries_askar.*
import aries_askar.EntryListHandle
import aries_askar.KeyEntryListHandle
import aries_askar.LocalKeyHandle
import aries_askar.ScanHandle
import aries_askar.SessionHandle
import aries_askar.StoreHandle
import askar.Askar
import kotlinx.cinterop.*
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking


class StoreHandle(val handle: StoreHandle) {

    suspend fun close() {
        Askar.store.storeClose(this.handle)
    }

    companion object {
        fun fromHandle(handle: StoreHandle?): askar.crypto.StoreHandle? {
            if (handle != null)
                return StoreHandle(handle)
            return null
        }
    }
}

class ScanHandle(val handle: ScanHandle) {

    fun free() {
        Askar.scan.free(this.handle)
    }

    companion object {
        fun fromHandle(handle: ScanHandle?): askar.crypto.ScanHandle? {
            if (handle != null)
                return ScanHandle(handle)
            return null
        }
    }
}

class SessionHandle(val handle: SessionHandle) {

    suspend fun close(commit: Boolean): Long {
        val h = this.handle
        val code: Long
        runBlocking {
            val c = async {Askar.session.sessionClose(h, commit)}
            code = c.await()
        }
        return code
    }


    companion object {
        fun fromHandle(handle: SessionHandle?): askar.crypto.SessionHandle? {
            if (handle != null)
                return SessionHandle(handle)
            return null
        }
    }
}

class EntryListHandle(val handle: EntryListHandle) {

    fun getCategory(index: Int): String {
        return Askar.entryList.getCategory(index, this.handle)
    }

    fun getName(index: Int): String {
        return Askar.entryList.getName(index, this.handle)
    }

    fun getValue(index: Int): String {
        return Askar.entryList.getValue(index, this.handle)
    }

    fun getTags(index: Int): String? {
        return Askar.entryList.getTags(index, handle)
    }

    fun free() {
        Askar.entryList.free(this.handle)
    }

    companion object {
        fun fromHandle(handle: EntryListHandle?): askar.crypto.EntryListHandle? {
            if(handle?._0 == null)
                return null
            return EntryListHandle(handle)
        }
    }
}

class KeyEntryListHandle(val handle: KeyEntryListHandle) {

    fun getAlgorithm(index: Int): String {
        return Askar.keyEntryList.getAlgorithm(index, this.handle)
    }

    fun getName(index: Int): String {
        return Askar.keyEntryList.getName(index, this.handle)
    }

    fun getTags(index: Int): String? {
        return Askar.keyEntryList.getTags(index, this.handle)
    }

    fun getMetadata(index: Int): String? {
        return Askar.keyEntryList.getMetadata(index, this.handle)
    }

    fun loadKey(index: Int): askar.crypto.LocalKeyHandleKot {
        return LocalKeyHandleKot(Askar.keyEntryList.loadLocal(index, this.handle))
    }

    fun free() {
        Askar.keyEntryList.free(this.handle)
    }

    companion object {
        fun fromHandle(handle: KeyEntryListHandle?): askar.crypto.KeyEntryListHandle? {
            if(handle != null)
                return KeyEntryListHandle(handle)
            return null
        }
    }
}
class LocalKeyHandleKot(val handle: LocalKeyHandle)  {

    fun free() {
        Askar.key.keyFree(this.handle)
        nativeHeap.free(handle)
    }

    companion object {
        fun fromHandle(handle: LocalKeyHandle?): askar.crypto.LocalKeyHandleKot? {
            if (handle != null)
                return LocalKeyHandleKot(handle)
            return null
        }
    }

//    object LocalKeyHandleAsStringSerializer : KSerializer<LocalKeyHandle> {
//        override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("handle", PrimitiveKind.STRING)
//        override fun serialize(encoder: Encoder, value: LocalKeyHandle) {
//            val count = value._0!!.reinterpret<FfiStrVar>().pointed.value!!.toKString().length
//            println(count)
//            val temp = value._0!!.pointed
//            val s = value._0!!.reinterpret<ByteVar>()
//            println()
//            encoder.encodeString("test")
//        }
//
//        override fun deserialize(decoder: Decoder): LocalKeyHandle {
//            val s = decoder.decodeString()
//            val h = cValue<LocalKeyHandle> {
//                //TODO: s needs to be converted back to a pointer
//               _0 = null
//            }
//            h.useContents {
//                return this
//            }
//        }
//    }


}





