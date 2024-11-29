package askar

import kotlinx.serialization.Serializable

@Serializable
class AskarError(
    val code: Long,
    override val message: String
) : Exception(
    "Askar Error: $code; $message"
)