@file:OptIn(UnsafeNumber::class)

package askar.Store

import askar.Askar
import askar.crypto.SessionHandle
import askar.crypto.StoreHandle
import kotlinx.cinterop.UnsafeNumber
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

@OptIn(UnsafeNumber::class)
class OpenSession(private val store: StoreHandle, private val profile: String? = null, private val isTxn: Boolean) {
    //TODO: Implement session not done in javascript yet
    private var session: SessionHandle? = null

    suspend fun open(): Session {
        if (this.session != null) throw Error("Session already opened")
        val sessionHandle = Askar.session.sessionStart(store.handle, profile, isTxn)
        return Session( sessionHandle, this.isTxn )
    }
}