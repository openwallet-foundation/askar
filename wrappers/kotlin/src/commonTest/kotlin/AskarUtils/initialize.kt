package tech.indicio.holdr.AskarUtils

import askar.Askar.Companion.mapToJsonObject
import askar.Store.EntryObject
import askar.Store.KdfMethod
import askar.Store.Store
import askar.Store.StoreKeyMethod
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

fun getRawKey(): String? {
    return Store.generateRawKey("00000000000000000000000000000My1")
}

val firstEntry = EntryObject("category-one", "test-entry", tags =
mapOf(
    Pair("~plaintag", JsonPrimitive("a")),
    Pair("enctag", JsonPrimitive("b"))
).mapToJsonObject().toString() , value = "foo"
)


val secondEntry = EntryObject("category-one", "secondEntry", tags =
mapOf(
    Pair("~plaintag", JsonPrimitive("a")),
    Pair("enctag",JsonPrimitive("b"))
).mapToJsonObject().toString(), value = buildJsonObject {
    put("foo", "bar")
}.toString())


//     const thirdEntry = {
//        category: 'category-one',
//        name: 'thirdEntry',
//        value: { foo: 'baz' },
//        tags: { '~plaintag': 'a', enctag: 'b' },
//    }


const val testStoreUri = "sqlite://local.db"

suspend fun setupWallet(): Store {
    val key = getRawKey() ?: throw Error("Key came back as null")
    return Store.provision(
        recreate = true,
        uri = testStoreUri,
        keyMethod = StoreKeyMethod(KdfMethod.Raw),
        passkey = key
    )
}

