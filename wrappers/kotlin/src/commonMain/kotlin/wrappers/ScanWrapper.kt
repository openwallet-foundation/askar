package askar.wrappers

import aries_askar.*
import askar.Askar
import askar.Askar.Companion.assertNoError
import askar.Askar.Companion.getErrorCode
import askar.crypto.EntryListHandle
import kotlinx.cinterop.*
import kotlinx.serialization.json.JsonObject
import kotlin.coroutines.Continuation
import kotlin.coroutines.suspendCoroutine

@OptIn(UnsafeNumber::class)
class ScanWrapper {

    fun free(handle: ScanHandle) {
        val errorCode = askar_scan_free(handle)
        assertNoError(errorCode)
    }

    suspend fun scanStart(
        handle: StoreHandle,
        limit: Int,
        offset: Int,
        tagFilter: JsonObject,
        profile: String?,
        category: String
    ) = suspendCoroutine<askar.crypto.ScanHandle> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()


        val errorCode = askar_scan_start(
            handle, profile, category, tagFilter.toString(), offset.toLong(), limit.toLong(),
            staticCFunction { callBackId, errorCode, scanHandle ->
                val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<askar.crypto.ScanHandle>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(assertNoError(errorCode, cont!!))
                    cont.resumeWith(Result.success(askar.crypto.ScanHandle(scanHandle)))
            }, contPtr.toLong()
        )
        assertNoError(errorCode, continuation)
    }

    class ScanNextProps(val memScope: MemScope, val cont: Continuation<EntryListHandle?>)

    suspend fun scanNext(handle: ScanHandle, memScope: MemScope) = suspendCoroutine<EntryListHandle?> { continuation ->
        val stableRef = StableRef.create(ScanNextProps(memScope, continuation))
        val contPtr = stableRef.asCPointer()
        //Try writing the handle to an out variable
        val errorCode = askar_scan_next(handle, staticCFunction { callBackId, errorCode, entryHandle ->
            val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<ScanNextProps>()
            val props = contRef?.get()
            val cont = props?.cont
            val scope = props?.memScope
            contRef?.dispose()
            if(assertNoError(errorCode, cont!!)) {
                val h = entryHandle.getPointer(scope!!).pointed
                if (h._0 == null) {
                    cont.resumeWith(Result.success(null))
                } else {
                    val handleCopy = EntryListHandle(h)
                    cont.resumeWith(Result.success(handleCopy))
                }
            }
        }, contPtr.toLong())
        assertNoError(errorCode, continuation)
    }
}