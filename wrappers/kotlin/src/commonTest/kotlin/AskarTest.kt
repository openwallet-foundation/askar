package tech.indicio.holdr


import askar.Askar.Companion.mapToJsonObject
import askar.Store.*
import askar.crypto.Key
import askar.enums.KeyAlgs
import kotlinx.cinterop.memScoped
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import tech.indicio.holdr.AskarUtils.*
import kotlin.test.*
import kotlin.test.Test


class AskarTest {

    private lateinit var store: Store


    @BeforeTest
    fun beforeEach() {
        runBlocking {
            store = setupWallet()
        }
    }

    @AfterTest
    fun afterEach() {
        runBlocking {
            store.close(true)
        }
    }

    @Test
    fun argon2imod() {
        runBlocking {
            val argonStore = Store.provision(
                recreate = true,
                passkey = "abc",
                uri = testStoreUri + "1", //Cannot have duplicate URI otherwise error is thrown
                keyMethod = StoreKeyMethod(KdfMethod.Argon2IMod),
                profile = "test"
            )

            val session = argonStore.openSession()
            assertNull(session.fetch("unknownCategory", "unknownKey"))
            argonStore.close()
        }
    }

    @Test
    fun argon2iint() {
        runBlocking {
            val argonStore = Store.provision(
                recreate = true,
                passkey = "abc",
                uri = testStoreUri + "1", //Cannot have duplicate URI otherwise error is thrown
                keyMethod = StoreKeyMethod(KdfMethod.Argon2IInt),
                profile = "test"
            )

            val session = argonStore.openSession()
            assertNull(session.fetch("unknownCategory", "unknownKey"))
            argonStore.close()
        }
    }

    @Test
    fun rekey() {
        runBlocking {
            val initialKey = Store.generateRawKey("1234") ?: throw Error("Key came back as null")
            val storage = "./tmp"
            var newStore = Store.provision(
                recreate = true,
                profile = "rekey",
                uri = "sqlite://$storage/rekey.db",
                keyMethod = StoreKeyMethod(KdfMethod.Raw),
                passkey = initialKey
            )
            val newKey = Store.generateRawKey("12345") ?: throw Error("Key came back as null")
            newStore.rekey(StoreKeyMethod(KdfMethod.Raw), newKey)
            newStore.close()
            assertFails {
                Store.open(
                    profile = "rekey",
                    uri = "sqlite://$storage/rekey.db",
                    keyMethod = StoreKeyMethod(KdfMethod.Raw),
                    passkey = initialKey
                )
            }
            newStore = Store.open(
                profile = "rekey",
                uri = "sqlite://$storage/rekey.db",
                keyMethod = StoreKeyMethod(KdfMethod.Raw),
                passkey = newKey
            )
            newStore.close(true)
        }
    }

    @Test
    fun insert() {
        runBlocking {
            val session = store.openSession()
            session.insert(
                firstEntry.category,
                firstEntry.name,
                value = firstEntry.value,
                tags = firstEntry.tags
            )
            assertEquals(1, session.count(firstEntry.category, firstEntry.tags))

            session.close()
        }
    }

    @Test
    fun replace() {
        runBlocking {
            val session = store.openSession()
            session.insert(
                firstEntry.category,
                firstEntry.name,
                value = firstEntry.value,
                tags = firstEntry.tags
            )
            assertEquals(1, session.count(firstEntry.category, firstEntry.tags))

            val updatedEntry = EntryObject(firstEntry.category, firstEntry.name, value = "bar", tags = "{\"foo\": \"bar\"}"
            )
            println(updatedEntry)
            session.replace(
                updatedEntry.category,
                updatedEntry.name,
                value = updatedEntry.value,
                tags = updatedEntry.tags
            )
            assertEquals(1, session.count(updatedEntry.category, updatedEntry.tags))
            session.close()
        }
    }

    @Test
    fun remove() {
        runBlocking {
            val session = store.openSession()
            session.insert(
                firstEntry.category,
                firstEntry.name,
                value = firstEntry.value,
                tags = firstEntry.tags
            )

            assertEquals(1, session.count(firstEntry.category, firstEntry.tags))

            session.remove(firstEntry.category, firstEntry.name)

            assertEquals(0, session.count(firstEntry.category, firstEntry.tags))

            session.close()
        }
    }

    @Test
    fun removeAll() {
        runBlocking {
            val session = store.openSession()
            session.insert(
                firstEntry.category,
                firstEntry.name,
                value = firstEntry.value,
                tags = firstEntry.tags
            )
            session.insert(
                secondEntry.category,
                secondEntry.name,
                value = secondEntry.value,
                tags = secondEntry.tags
            )

            assertEquals(2, session.count(firstEntry.category, firstEntry.tags))

            session.removeAll(firstEntry.category)

            assertEquals(0, session.count(firstEntry.category, firstEntry.tags))

            session.close()
        }
    }

    @Test
    fun scan() {
        runBlocking {
            val session = store.openSession()
            session.insert(
                firstEntry.category,
                firstEntry.name,
                value = firstEntry.value,
                tags = firstEntry.tags
            )
            session.insert(
                category = secondEntry.category,
                name = secondEntry.name,
                value = secondEntry.value,
                tags = secondEntry.tags
            )

            val found = store.scan(category = firstEntry.category).fetchAll()

            assertEquals(2, found.size)

            session.close()
        }
    }

    @Test
    fun transactionBasic() {
        runBlocking {
            val txn = store.openSession(true)

            txn.insert(
                firstEntry.category,
                firstEntry.name,
                value = firstEntry.value,
                tags = firstEntry.tags
            )

            assertEquals(1, txn.count(firstEntry.category, firstEntry.tags))

            val ret = txn.fetch(firstEntry.category, firstEntry.name) ?: throw Error("should not happen")

            assertEquals(ret, firstEntry)

            val found = txn.fetchAll(firstEntry.category)

            assertEquals(found[0], firstEntry)

            txn.commit()

            val session = store.openSession()

            val fetch = session.fetch(firstEntry.category, firstEntry.name)

            assertEquals(fetch, firstEntry)

            session.close()
        }
    }

    @Test
    fun keyStore() {
        runBlocking {
            val session = store.openSession()

            val key = Key.generate(KeyAlgs.Ed25519)

            val keyName = "testKey"

            session.insertKey(keyName, key, metadata = "metadata", tags = mapOf(Pair("a", JsonPrimitive("b"))).mapToJsonObject().toString())

            val fetchedKey = session.fetchKey(keyName)

            assertEquals(
                fetchedKey,
                KeyEntryObject(KeyAlgs.Ed25519.alg, keyName, "metadata", mapOf(Pair("a", JsonPrimitive("b"))).mapToJsonObject().toString())
            )

            session.updateKey(keyName, "updated metadata", tags = mapOf(Pair("a", JsonPrimitive("c"))).mapToJsonObject().toString())

            val updatedFetch = session.fetchKey(keyName)

            assertNotEquals(fetchedKey, updatedFetch)

            assertEquals(key.jwkThumbprint(), fetchedKey?.key?.jwkThumbprint())

            val found = session.fetchAllKeys(
                KeyAlgs.Ed25519,
                key.jwkThumbprint(),
                mapOf(Pair("a", JsonPrimitive("c"))).mapToJsonObject().toString(),
            )

            assertEquals(found[0], updatedFetch)

            session.removeKey(keyName)

            assertNull(session.fetchKey(keyName))

            session.close()

            key.handle().free()
            fetchedKey?.key!!.handle().free()
            updatedFetch?.key!!.handle().free()
            found.forEach { entry -> entry.key!!.handle().free() }
        }
    }


    @Test
    fun profile() {
        runBlocking {
            val session = store.openSession()
            session.insert(firstEntry.category, firstEntry.name, value = firstEntry.value, tags = firstEntry.tags)
            session.close()

            val profile = store.createProfile()!!

            val session2 = store.session(profile).open()
            assertEquals(0, session2.count(firstEntry.category, firstEntry.tags))
            session2.insert(firstEntry.category, firstEntry.name, value = firstEntry.value, tags = firstEntry.tags)
            assertEquals(1, session2.count(firstEntry.category, firstEntry.tags))
            session2.close()

            //TODO: Find out why this fails
//            if(!store.uri().contains(":memory:")){
//                val key = getRawKey()!!
//                val store2 = Store.open(testStoreUri, StoreKeyMethod(KdfMethod.Raw), passkey = key)
//                val session3 = store2.openSession()
//                assertEquals(0, session3.count(firstEntry.category, firstEntry.tags))
//                session3.close()
//                store2.close()
//            }

            assertFails { store.createProfile(profile) }

            val session4 = store.session(profile).open()
            assertEquals(1, session4.count(firstEntry.category, firstEntry.tags))
            session4.close()

            store.removeProfile(profile)

            val session5 = store.session(profile).open()
            assertEquals(0, session5.count(firstEntry.category, firstEntry.tags))
            session5.close()

            val session6 = store.session("unknown profile").open()
            assertFails { session6.count(firstEntry.category, firstEntry.tags) }
            session6.close()

            val session7 = store.session(profile).open()
            assertEquals(0, session7.count(firstEntry.category, firstEntry.tags))
            session7.close()
        }
    }
}