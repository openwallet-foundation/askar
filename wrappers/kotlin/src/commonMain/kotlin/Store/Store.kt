package askar.Store

import askar.Askar
import askar.crypto.StoreHandle
import kotlinx.cinterop.UnsafeNumber
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject

@OptIn(UnsafeNumber::class)
class Store(private val handle: StoreHandle, private val uri: String) {
    private var opener: OpenSession? = null

    /**
     * The store handle object for this store
     */
    fun handle(): StoreHandle {
        return handle
    }

    /**
     * The uri for this store
     */
    fun uri(): String {
        return uri
    }

    /**
     * Creates a new profile in the store
     * @param name the name of the profile to create
     * @return A string of the profile that was created
     */
    suspend fun createProfile(name: String = ""): String? {
        return Askar.store.storeCreateProfile(handle.handle, name)
    }

    /**
     * Removes the given profile from the store
     * @param name the name of the profile to remove
     * @return true if successful false otherwise
     */
    suspend fun removeProfile(name: String): Boolean {
        return Askar.store.storeRemoveProfile(this.handle.handle, name)
    }

    /**
     * Changes the passkey to the store
     * @param keyMethod StoreKeyMethod object denoting the encryption key method to use. Takes in a KdfKeyMethod
     * @param passkey the password to open this store. Recommended to use generate raw key create a strong key
     * @return True if successful false otherwise
     */
    suspend fun rekey(keyMethod: StoreKeyMethod = StoreKeyMethod(KdfMethod.Argon2IInt), passkey: String): Boolean {
        val code = Askar.store.storeRekey(handle.handle, keyMethod, passkey)
        return code == 0L
    }

    /**
     * closes the current store for any operations
     * @param remove whether the store should be removed from storage
     * @return This function only returns true if the uri has been removed from the store
     */
    suspend fun close(remove: Boolean = false): Boolean {
        this.opener = null
        Askar.store.storeClose(handle.handle)
        if (remove) return remove(uri)
        return false
    }

    /**
     * Creates a session on this store with the given profile
     * @param profile the profile with which to create the session
     * @return the OpenSession object to the newly created session
     */
    fun session(profile: String? = null): OpenSession {
        return OpenSession(this.handle, profile, false)
    }

    /**
     * Creates a transaction on this store with the given profile
     * @param profile the profile with which to create the transaction
     * @return the OpenSession object to the newly created transaction
     */
    fun transaction(profile: String = "local"): OpenSession {
        return OpenSession(this.handle, profile, true)
    }

    /**
     * Creates and opens a session on this store
     * @throws Error if this store has been closed or is in invalid state
     * @param isTxn whether this session should be a transaction
     * @return The created session
     */
    suspend fun openSession(isTxn: Boolean = false): Session {
        this.opener = OpenSession(this.handle, isTxn = isTxn)
        return opener!!.open()
    }

    fun scan(
        category: String,
        tagFilter: JsonObject = buildJsonObject { },
        offset: Int = 0,
        limit: Int = -1,
        profile: String? = null
    ): Scan {
        return Scan(profile, category, tagFilter, offset, limit, this)
    }


    companion object {
        /**
         * Generates a raw key for use else where
         * @param seed input to consistently generate same key
         * @return The raw key as a string
         */
        fun generateRawKey(seed: String): String? {
            return Askar.store.storeGenerateRawKey(seed)
        }

        /**
         * Initializes a store and returns the created store
         * @throws Error if uri is invalid
         * @param uri String mapping to storage location i.e. sqlite://local.db
         * @param keyMethod StoreKeyMethod object denoting the encryption key method to use. Takes in a KdfKeyMethod
         * @param profile string identifying this store in storage
         * @param passkey the password to open this store. Recommended to use generate raw key create a strong key
         * @param recreate whether this should recreate a removed store
         * @return The newly created Store object
         */
        suspend fun provision(
            uri: String,
            keyMethod: StoreKeyMethod = StoreKeyMethod(KdfMethod.None),
            passkey: String = "1234",
            profile: String? = null,
            recreate: Boolean
        ): Store {
            val h = Askar.store.storeProvision(uri, passkey, profile, keyMethod, recreate)
            val handle = StoreHandle(h.storeHandle)
            return Store(handle, uri)
        }

        /**
         * Opens a store that has already been provisioned with given parameters
         * @throws Error if store has not been provisioned with given parameters
         * @throws Error if passkey is incorrect for store
         * @param uri String mapping to storage location i.e. sqlite://local.db
         * @param keyMethod StoreKeyMethod object denoting the encryption key method to use. Takes in a KdfKeyMethod
         * @param profile string identifying this store in storage
         * @return A opened store object
         */
        suspend fun open(
            uri: String,
            keyMethod: StoreKeyMethod = StoreKeyMethod(KdfMethod.Argon2IInt),
            passkey: String = "1234",
            profile: String? = null
        ): Store {
            val h = Askar.store.storeOpen(uri, passkey, profile, keyMethod)
            val handle = StoreHandle(h.storeHandle)
            return Store(handle, uri)
        }

        /**
         * Removes a store from the local system
         * @throws Error if provided invalid uri
         * @param uri: String mapping to storage location i.e. sqlite://local.db
         * @return true if successful false otherwise
         */
        suspend fun remove(uri: String): Boolean {
            return Askar.store.storeRemove(uri)
        }
    }


}