package askar.wrappers

import aries_askar.*
import askar.Askar
import askar.Askar.Companion.secretBufferToByteArray
import askar.Askar.Companion.secretBufferToString
import kotlinx.cinterop.*
import platform.posix.int32_t
import platform.posix.int32_tVar
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class EntryListWrapper {

    fun getCategory(index: Int, handle: EntryListHandle): String {
        memScoped {
            val cHandle = cValue<EntryListHandle> {
                _0 = handle._0
            }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_entry_list_get_category(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value!!.toKString()
        }
    }

    fun getName(index: Int, handle: EntryListHandle): String {
        memScoped {
            val cHandle = cValue<EntryListHandle> {
                _0 = handle._0
            }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_entry_list_get_name(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value!!.toKString()
        }
    }

    fun getValue(index: Int, handle: EntryListHandle): String {
        memScoped {
            val cHandle = cValue<EntryListHandle> {
                _0 = handle._0
            }
            val out = alloc<SecretBuffer>()
            val errorCode = askar_entry_list_get_value(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return secretBufferToString(out)
        }
    }

    fun getTags(index: Int, handle: EntryListHandle): String? {
        memScoped {
            val cHandle = cValue<EntryListHandle> {
                _0 = handle._0
            }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_entry_list_get_tags(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value?.toKString()

        }
    }

    fun free(handle: EntryListHandle) {
        memScoped {
            val cHandle = cValue<EntryListHandle> {
                _0 = handle._0
            }
            askar_entry_list_free(cHandle)
        }
    }

    fun entryListCount(handle: EntryListHandle): int32_t {
        memScoped {
            val cHandle = cValue<EntryListHandle>{
                _0 = handle._0
            }
            val out = alloc<int32_tVar>()
            val errorCode = askar_entry_list_count(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value
        }
    }
}