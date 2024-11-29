package askar.wrappers


import aries_askar.*
import askar.Askar
import askar.Askar.Companion.getErrorCode
import kotlinx.cinterop.*
import platform.posix.int32_t
import platform.posix.int32_tVar

class KeyEntryListWrapper {

    fun getAlgorithm(index: Int, handle: KeyEntryListHandle): String {
        memScoped {
            val cHandle = cValue<KeyEntryListHandle> { _0 = handle._0 }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_key_entry_list_get_algorithm(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value!!.toKString()
        }
    }

    fun getName(index: Int, handle: KeyEntryListHandle): String {
        memScoped {
            val cHandle = cValue<KeyEntryListHandle> { _0 = handle._0 }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_key_entry_list_get_name(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value!!.toKString()
        }
    }

    fun getTags(index: Int, handle: KeyEntryListHandle): String? {
        memScoped {
            val cHandle = cValue<KeyEntryListHandle> { _0 = handle._0 }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_key_entry_list_get_tags(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value?.toKString()
        }
    }

    fun getMetadata(index: Int, handle: KeyEntryListHandle): String? {
        memScoped {
            val cHandle = cValue<KeyEntryListHandle> {
                _0 = handle._0
            }
            val out = alloc<CPointerVar<ByteVar>>()
            val errorCode = askar_key_entry_list_get_metadata(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value?.toKString()
        }
    }

    fun loadLocal(index: Int, handle: KeyEntryListHandle): LocalKeyHandle {
            val cHandle = cValue<KeyEntryListHandle> {
                _0 = handle._0
            }
            val out = nativeHeap.alloc<LocalKeyHandle>()
            val errorCode = askar_key_entry_list_load_local(cHandle, index, out.ptr)
            Askar.assertNoError(errorCode)
            return out
    }

    fun free(handle: KeyEntryListHandle) {
        memScoped {
            val cHandle = cValue<KeyEntryListHandle> {
                _0 = handle._0
            }
            askar_key_entry_list_free(cHandle)
        }
    }

    fun count(handle: KeyEntryListHandle): int32_t {
        memScoped {
            val cHandle = cValue<KeyEntryListHandle> {
                _0 = handle._0
            }
            val out = alloc<int32_tVar>()
            val errorCode = askar_key_entry_list_count(cHandle, out.ptr)
            Askar.assertNoError(errorCode)
            return out.value
        }
    }


}