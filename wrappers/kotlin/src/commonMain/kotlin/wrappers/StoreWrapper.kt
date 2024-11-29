@file:OptIn(UnsafeNumber::class, ExperimentalUnsignedTypes::class, UnsafeNumber::class)

package askar.wrappers

import aries_askar.*
import askar.Askar
import askar.Askar.Companion.getErrorCode
import askar.Store.StoreKeyMethod
import kotlinx.cinterop.*
import platform.posix.uint8_tVar
import kotlin.coroutines.Continuation
import kotlin.coroutines.suspendCoroutine

@OptIn(UnsafeNumber::class)
class StoreWrapper {

    // STORE PROVISION
    class StoreProvisionResponse(
        val callbackId: CallbackId,
        val storeHandle: StoreHandle,
        val errorCode: ErrorCode
    )

    suspend fun storeProvision(
        specUri: String,
        passKey: String,
        profile: String?,
        keyMethod: StoreKeyMethod,
        recreate: Boolean
    ): StoreProvisionResponse = suspendCoroutine { continuation ->
        val contStableRef = StableRef.create(continuation)
        val contPtr = contStableRef.asCPointer()
        val bool = if (recreate) 1 else 0

        val errorCode = askar_store_provision(
            specUri,
            keyMethod.toUri(),
            passKey,
            profile,
            bool.toByte(),
            staticCFunction { callbackId, errorCode, storeHandle ->
                val response = StoreProvisionResponse(callbackId, storeHandle, errorCode)
                val contRef = callbackId.toCPointer<CPointed>()?.asStableRef<Continuation<StoreProvisionResponse>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(Askar.assertNoError(errorCode, cont!!))
                    cont.resumeWith(Result.success(response))
            },
            contPtr.toLong()
        )
        Askar.assertNoError(errorCode, continuation)
    }

    // STORE CLOSE
    suspend fun storeClose(storeHandle: StoreHandle) = suspendCoroutine<Askar.ErrorCodes> { continuation ->
        val contStableRef = StableRef.create(continuation)
        val contPtr = contStableRef.asCPointer()

        val errorCode = askar_store_close(
            storeHandle,
            staticCFunction { callbackId, errorCode ->
                val contRef = callbackId.toCPointer<CPointed>()?.asStableRef<Continuation<Askar.ErrorCodes>>()
                contRef?.get()?.resumeWith(Result.success(getErrorCode(errorCode)))
                contRef?.dispose()
            },
            contPtr.toLong()
        )
        Askar.assertNoError(errorCode, continuation)
    }

    suspend fun storeOpen(
        specUri: String,
        passKey: String,
        profile: String?,
        keyMethod: StoreKeyMethod
    ) = suspendCoroutine<StoreProvisionResponse> { continuation ->
        val contStableRef = StableRef.create(continuation)
        val contPtr = contStableRef.asCPointer()

        val errorCode = askar_store_open(
            specUri,
            keyMethod.toUri(),
            passKey,
            profile,
            staticCFunction { callbackId, errorCode, storeHandle ->
                val response = StoreProvisionResponse(callbackId, storeHandle, errorCode)
                val contRef = callbackId.toCPointer<CPointed>()?.asStableRef<Continuation<StoreProvisionResponse>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(Askar.assertNoError(errorCode, cont!!))
                    cont.resumeWith(Result.success(response))
            },
            contPtr.toLong()
        )
        Askar.assertNoError(errorCode, continuation)
    }

    suspend fun storeRemove(specUri: String) = suspendCoroutine<Boolean> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()

        val errorCode = askar_store_remove(
            specUri,
            staticCFunction { callbackId, errorCode, bool ->
                val contRef = callbackId.toCPointer<CPointed>()?.asStableRef<Continuation<Boolean>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(Askar.assertNoError(errorCode, cont!!))
                    cont.resumeWith(Result.success(bool.toBoolean()))
            },
            contPtr.toLong()
        )
        Askar.assertNoError(errorCode, continuation)
    }

    suspend fun storeCreateProfile(handle: StoreHandle, profile: String) =
        suspendCoroutine<String?> { continuation ->
            val stableRef = StableRef.create(continuation)
            val contPtr = stableRef.asCPointer()

            val errorCode = askar_store_create_profile(
                handle, profile,
                staticCFunction { callbackId, errorCode, profile ->
                    val contRef = callbackId.toCPointer<CPointed>()?.asStableRef<Continuation<String?>>()
                    val cont = contRef?.get()
                    contRef?.dispose()
                    if(Askar.assertNoError(errorCode, cont!!)) {
                        val temp = profile?.toKString()
                        cont.resumeWith(Result.success(temp))
                    }
                },
                contPtr.toLong()
            )
            Askar.assertNoError(errorCode, continuation)
        }

    suspend fun storeGetProfileName(handle: StoreHandle) = suspendCoroutine<String?> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()

        val errorCode = askar_store_get_profile_name(
            handle,
            staticCFunction { callbackID, errorCode, name ->
                val contRef = callbackID.toCPointer<CPointed>()?.asStableRef<Continuation<String?>>()
                val cont = contRef?.get()
                contRef?.dispose()
                if(Askar.assertNoError(errorCode, cont!!)) {
                    val temp = name?.toKString()
                    cont.resumeWith(Result.success(temp))
                }
            },
            contPtr.toLong()
        )
        Askar.assertNoError(errorCode, continuation)
    }

    suspend fun storeRemoveProfile(handle: StoreHandle, name: String) = suspendCoroutine<Boolean> { continuation ->
        val stableRef = StableRef.create(continuation)
        val contPtr = stableRef.asCPointer()

        val errorCode = askar_store_remove_profile(handle, name, staticCFunction { callBackId, errorCode, removed ->
            val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<Boolean>>()
            val cont = contRef?.get()
            contRef?.dispose()
            if(Askar.assertNoError(errorCode, cont!!))
                cont.resumeWith(Result.success(removed.toBoolean()))
        }, contPtr.toLong())
        Askar.assertNoError(errorCode, continuation)

    }

    suspend fun storeRekey(handle: StoreHandle, keyMethod: StoreKeyMethod, passKey: String) =
        suspendCoroutine<ErrorCode> { continuation ->
            val stableRef = StableRef.create(continuation)
            val contPtr = stableRef.asCPointer()

            val errorCode =
                askar_store_rekey(handle, keyMethod.toUri(), passKey, staticCFunction { callBackId, errorCode ->
                    val contRef = callBackId.toCPointer<CPointed>()?.asStableRef<Continuation<ErrorCode>>()
                    val cont = contRef?.get()
                    if(Askar.assertNoError(errorCode, cont!!))
                        cont.resumeWith(Result.success(errorCode))
                }, contPtr.toLong())
            Askar.assertNoError(errorCode, continuation)
        }


    fun storeGenerateRawKey(key: String): String? {
        var errorCode: Long = 0
        var rawKey: String? = null
        memScoped {
            val cString = key.cstr
            val uIntBuffer = allocArray<uint8_tVar>(cString.size)
            for (i in 0..cString.size) {
                uIntBuffer[i] = cString.ptr[i].toUByte()
            }
            val buffer = cValue<ByteBuffer> {
                data = uIntBuffer
                len = cString.size.toLong()
            }
            val out = alloc<CPointerVar<ByteVar>>()
            errorCode = askar_store_generate_raw_key(buffer, out.ptr)
            rawKey = out.value!!.toKString()
        }
        Askar.assertNoError(errorCode)
        return rawKey
    }

}