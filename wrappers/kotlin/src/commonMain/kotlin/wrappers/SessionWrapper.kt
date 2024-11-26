package askar.wrappers

import aries_askar.*

import aries_askar.LocalKeyHandle
import askar.Askar
import askar.Askar.Companion.stringToByteBuffer
import askar.crypto.EntryListHandle
import askar.crypto.Key
import askar.crypto.KeyEntryListHandle
import askar.enums.EntryOperation
import askar.enums.KeyAlgs
import kotlinx.cinterop.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import platform.posix.uint8_tVar
import kotlin.coroutines.Continuation

import kotlin.coroutines.suspendCoroutine

@OptIn(UnsafeNumber::class)
class SessionWrapper {

    suspend fun sessionClose(handle: SessionHandle, commit: Boolean) = suspendCoroutine<ErrorCode> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()
        val bool = if (commit) 1 else 0

        val errorCode = askar_session_close(
            handle, bool.toByte(), staticCFunction { callBackId, errorCode ->
                val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<ErrorCode>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(Askar.assertNoError(errorCode, cont!!))
                    cont.resumeWith(Result.success(errorCode))
            },
            contPtr.toLong()
        )
        Askar.assertNoError(errorCode, continuation)
    }

    suspend fun sessionCount(handle: SessionHandle, category: String, tagFilter: String) =
        suspendCoroutine<Long> { continuation ->
            val stableRef = StableRef.create(continuation)
            val contPtr = stableRef.asCPointer()

            val errorCode =
                askar_session_count(handle, category, tagFilter, staticCFunction { callBackId, errorCode, count ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<Long>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!))
                        cont.resumeWith(Result.success(count))

                }, contPtr.toLong())

            Askar.assertNoError(errorCode, continuation)
        }

    suspend fun sessionFetch(
        handle: SessionHandle,
        category: String,
        name: String,
        forUpdate: Boolean,
    ) =
        suspendCoroutine<EntryListHandle?> { continuation ->
            val stableRef = StableRef.create(continuation)
            val contPtr = stableRef.asCPointer()
            val bool = if (forUpdate) 1 else 0
            val errorCode = askar_session_fetch(
                handle,
                category,
                name,
                bool.toByte(),
                staticCFunction { callBackId, errorCode, entryListHandle ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<EntryListHandle?>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!)) {
                        val temp = nativeHeap.alloc<aries_askar.EntryListHandle>()
                        val h = entryListHandle.place(temp.ptr).pointed
                        if (h._0 == null)
                            cont.resumeWith(Result.success(null))
                        else {
                            val entryList = EntryListHandle(h)
                            cont.resumeWith(Result.success(entryList))
                        }
                    }
                },
                contPtr.toLong()
            )
            Askar.assertNoError(errorCode, continuation)
        }

    suspend fun fetchAll(
        handle: SessionHandle,
        category: String,
        tagFilter: String,
        limit: Long,
        forUpdate: Boolean,
    ) =
        suspendCoroutine<EntryListHandle?> { continuation ->
            val stableRef = StableRef.create( continuation)
            val contPtr = stableRef.asCPointer()
            val bool = if (forUpdate) 1 else 0

            val errorCode = askar_session_fetch_all(
                handle, category, tagFilter, limit, bool.toByte(),
                staticCFunction { callBackId, errorCode, entryListHandle ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<EntryListHandle?>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!)) {
                        val temp = nativeHeap.alloc<aries_askar.EntryListHandle>()
                        val h = entryListHandle.place(temp.ptr).pointed
                        if (h._0 == null)
                            cont.resumeWith(Result.success(null))
                        else {
                            val entryList = EntryListHandle.fromHandle(h)
                            cont.resumeWith(Result.success(entryList))
                        }
                    }
                }, contPtr.toLong()
            )
            Askar.assertNoError(errorCode, continuation)
        }

    suspend fun sessionUpdate(
        handle: SessionHandle,
        category: String,
        name: String,
        expiryMs: Long,
        tags: String = "{}",
        value: String = "",
        operation: EntryOperation
    ) = suspendCoroutine<ErrorCode> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()
        memScoped {
            val buffer = stringToByteBuffer(value, this)
            val errorCode = askar_session_update(
                handle,
                operation.ordinal.toByte(),
                category,
                name,
                buffer,
                tags,
                expiryMs,
                staticCFunction { callBackId, errorCode ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<ErrorCode>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!))
                        cont.resumeWith(Result.success(errorCode))
                },
                contPtr.toLong()
            )
            Askar.assertNoError(errorCode, continuation)
        }
    }

    suspend fun sessionRemoveAll(handle: SessionHandle, category: String, tagFilter: String) =
        suspendCoroutine<ErrorCode> { continuation ->
            val stableRef = StableRef.create(continuation)
            val contPtr = stableRef.asCPointer()

            val errorCode =
                askar_session_remove_all(handle, category, tagFilter, staticCFunction { callBackId, errorCode, _ ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<ErrorCode>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!))
                        cont.resumeWith(Result.success(errorCode))
                }, contPtr.toLong())
            Askar.assertNoError(errorCode, continuation)
        }

    suspend fun sessionInsertKey(
        handle: SessionHandle,
        name: String,
        key: Key,
        metadata: String? = null,
        tags: String = "{}",
        expiryMs: Long
    ) = suspendCoroutine<ErrorCode> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()
        val cHandle = cValue<LocalKeyHandle> {
            _0 = key.handle().handle._0
        }

        val errorCode = askar_session_insert_key(
            handle, cHandle, name, metadata, tags, expiryMs,
            staticCFunction { callBackId, errorCode ->
                val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<ErrorCode>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(Askar.assertNoError(errorCode, cont!!))
                    cont.resumeWith(Result.success(errorCode))
            }, contPtr.toLong()
        )
        Askar.assertNoError(errorCode, continuation)
    }

    suspend fun sessionFetchKey(handle: SessionHandle, name: String, forUpdate: Boolean) =
        suspendCoroutine<KeyEntryListHandle?> { continuation ->
            val stableRef = StableRef.create(continuation)
            val contPtr = stableRef.asCPointer()
            val bool = if (forUpdate) 1 else 0
            val errorCode = askar_session_fetch_key(
                handle, name, bool.toByte(),
                staticCFunction { callBackId, errorCode, key ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<KeyEntryListHandle?>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!)) {
                        val temp = nativeHeap.alloc<aries_askar.KeyEntryListHandle>()
                        val h = key.place(temp.ptr).pointed
                        if (h._0 == null)
                            cont.resumeWith(Result.success(null))
                        else
                            cont.resumeWith(Result.success(KeyEntryListHandle.fromHandle(h)))
                    }
                }, contPtr.toLong()
            )
            Askar.assertNoError(errorCode, continuation)
        }

    suspend fun sessionFetchAllKeys(
        handle: SessionHandle,
        algorithm: KeyAlgs?,
        thumbprint: String?,
        tagFilter: String?,
        limit: Long,
        forUpdate: Boolean,
    ) = suspendCoroutine<KeyEntryListHandle?> { continuation ->
        val stableRef = StableRef.create( continuation)
        val contPtr = stableRef.asCPointer()
        val bool = if (forUpdate) 1 else 0
        val errorCode =
            askar_session_fetch_all_keys(
                handle, algorithm?.alg, thumbprint, tagFilter, limit, bool.toByte(),
                staticCFunction { callBackId, errorCode, key ->
                    val contRef =
                        callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<KeyEntryListHandle?>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!)) {
                        val temp = nativeHeap.alloc<aries_askar.KeyEntryListHandle>()
                        val h = key.place(temp.ptr).pointed
                        if (h._0 == null)
                            cont.resumeWith(Result.success(null))
                        else
                            cont.resumeWith(Result.success(KeyEntryListHandle.fromHandle(h)))
                    }
                }, contPtr.toLong()
            )
        Askar.assertNoError(errorCode, continuation)
    }

    suspend fun sessionUpdateKey(
        handle: SessionHandle,
        name: String,
        metadata: String?,
        tags: String?,
        expiryMs: Long
    ) = suspendCoroutine<ErrorCode> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()

        memScoped {
            val errorCode = askar_session_update_key(
                handle, name, metadata, tags.toString(), expiryMs,
                staticCFunction { callBackId, errorCode ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<ErrorCode>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!))
                        cont.resumeWith(Result.success(errorCode))
                }, contPtr.toLong()
            )
            Askar.assertNoError(errorCode, continuation)
        }
    }

    suspend fun sessionRemoveKey(handle: SessionHandle, name: String) = suspendCoroutine<ErrorCode> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()

        memScoped {
            val errorCode = askar_session_remove_key(handle, name, staticCFunction { callBackId, errorCode ->
                val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<ErrorCode>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(Askar.assertNoError(errorCode, cont!!))
                    cont.resumeWith(Result.success(errorCode))
            }, contPtr.toLong())
            Askar.assertNoError(errorCode, continuation)
        }
    }

    suspend fun sessionStart(handle: StoreHandle, profile: String?, isTxn: Boolean) =
        suspendCoroutine<askar.crypto.SessionHandle> { continuation ->
            val stableRef = StableRef.create(continuation)
            val contPtr = stableRef.asCPointer()
            val bool = if (isTxn) 1 else 0

            val errorCode = askar_session_start(
                handle, profile, bool.toByte(),
                staticCFunction { callBackId, errorCode, handle ->
                    val contRef =
                        callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<askar.crypto.SessionHandle>>()
                    val cont = contRef?.get()
                    contRef?.dispose()

                    if(Askar.assertNoError(errorCode, cont!!))
                        cont.resumeWith(Result.success(askar.crypto.SessionHandle(handle)))
                }, contPtr.toLong()
            )
            Askar.assertNoError(errorCode, continuation)
        }
}