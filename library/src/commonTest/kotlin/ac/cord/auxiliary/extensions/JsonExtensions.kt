package ac.cord.auxiliary.extensions

import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.reflect.KClass

fun JsonElement.getValue(key: String): ByteArray {
    return getValueOrNull(key)!!
}

fun JsonElement.getValueOrNull(key: String): ByteArray? = try {
    jsonObject[key]?.jsonPrimitive?.content?.let { Hex.decode(it) }
} catch (e: Throwable) {
    null
}

fun JsonElement.getErrorDetails(key: String): Pair<KClass<out Throwable>, (Any) -> Boolean> {
    val error = jsonObject[key]!!.jsonObject

    return when (error["type"]!!.jsonPrimitive.content)  {
        "InvalidContributionError" -> {
            Pair(
                InvalidContributionException::class,
                { e ->
                    val invalidContributionException = e as? InvalidContributionException

                    val contrib = error["contrib"]?.jsonPrimitive?.content
                    val match = if (contrib != null) {
                        invalidContributionException?.signerId == error["signer_index"]?.jsonPrimitive?.intOrNull?.toBigInteger() && invalidContributionException?.contrib == contrib
                    } else {
                        invalidContributionException?.signerId == error["signer_index"]?.jsonPrimitive?.intOrNull?.toBigInteger()
                    }

                    if (!match) {
                        Logger.e("Expected: $error, actual: $e")
                    }
                    match
                }
            )

        }
        "value" -> {
            Pair(
                IllegalArgumentException::class,
                { e ->
                    val illegalArgumentException = e as? IllegalArgumentException

                    val match = illegalArgumentException?.message == error["message"]?.jsonPrimitive?.content

                    if (!match) {
                        Logger.e("Expected: ${error["message"]?.jsonPrimitive?.content}, actual: ${illegalArgumentException?.message}")
                    }

                    match
                }
            )
        }
        else -> {
            throw RuntimeException("Unsupported error type: $error")
        }
    }
}
