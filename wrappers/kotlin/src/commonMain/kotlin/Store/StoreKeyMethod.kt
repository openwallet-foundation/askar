package askar.Store

enum class KdfMethod(val method: String){
    Raw("raw"),
    None("None"),
    Argon2IMod("kdf:argon2i:mod"),
    Argon2IInt("kdf:argon2i:int")

}

class StoreKeyMethod(private val method: KdfMethod) {
    
    fun toUri(): String {
        return this.method.method
    }

}