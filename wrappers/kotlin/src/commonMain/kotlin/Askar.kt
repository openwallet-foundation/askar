@file:OptIn(UnsafeNumber::class, UnsafeNumber::class)

package askar


import aries_askar.*
import askar.wrappers.*
import kotlinx.cinterop.*
import kotlinx.serialization.json.*
import kotlin.coroutines.Continuation

class Askar {

    enum class ErrorCodes(val errorCode: ErrorCode) {
        Success(0),
        Backend(1),
        Busy(2),
        Duplicate(3),
        Encryption(4),
        Input(5),
        NotFound(6),
        Unexpected(7),
        Unsupported(8),
        Custom(100),
    }

    companion object {
        fun version(): String {
            return askar_version()!!.toKString()
        }

        private fun getErrorJson(): AskarError {
            memScoped {
                val jsonPointer = alloc<CPointerVar<ByteVar>>()
                askar_get_current_error(jsonPointer.ptr)
                val json = jsonPointer.value!!.toKString()
                return Json.decodeFromString<AskarError>(json)
            }
        }

        fun assertNoError(errorCode: ErrorCode){
            if (errorCode > 0L) {
                throw getErrorJson()
            }
        }

        fun <T> assertNoError(errorCode: ErrorCode, continuation: Continuation<T>): Boolean {
            if(errorCode > 0L) {
                continuation.resumeWith(Result.failure(getErrorJson()))
                return false
            }
            return true
        }

        fun getErrorCode(errorCode: ErrorCode): ErrorCodes {
            for(errCode in ErrorCodes.values())
                if(errCode.errorCode.equals(errorCode))
                    return errCode;
            throw Error("Could not find matching error code for $errorCode")
        }

        fun secretBufferToString(secretBuffer: SecretBuffer): String {
            val buffer = ByteArray(secretBuffer.len.toInt()){
                secretBuffer.data?.get(it)?.toByte()!!
            }
            return buffer.toKString()
        }


        fun secretBufferToByteArray(secretBuffer: SecretBuffer): ByteArray {
            val buffer = ByteArray(secretBuffer.len.toInt()) {
                secretBuffer.data!![it].toByte()
            }
            return buffer
        }

        fun stringToByteBuffer(string: String, scope: MemScope): CValue<ByteBuffer> {
            val cArr = scope.allocArray<UByteVar>(string.length){
                this.value = string[it].code.toUByte()
            }
            val byteBuffer = cValue<ByteBuffer> {
                data = cArr
                len = string.length.toLong()
            }
            return byteBuffer
        }

        fun byteArrayToByteBuffer(buffer: ByteArray, scope: MemScope): CValue<ByteBuffer> {
            val cArr = scope.allocArray<UByteVar>(buffer.size){
                this.value = buffer[it].toUByte()
            }
            val byteBuffer = cValue<ByteBuffer> {
                data = cArr
                len = buffer.size.toLong()
            }
            return byteBuffer
        }

        fun Map<String, JsonElement>.mapToJsonObject(): JsonObject {
            val map = this
            val json = buildJsonObject {
                map.forEach { entry ->
                    put(entry.key, entry.value)
                }
            }
            return json
        }




        val store = StoreWrapper()

        val keyEntryList = KeyEntryListWrapper()

        val entryList = EntryListWrapper()

        val scan = ScanWrapper()

        val session = SessionWrapper()

        val key = KeyWrapper()

        val cryptoBox = CryptoBoxWrapper()

    }
}

