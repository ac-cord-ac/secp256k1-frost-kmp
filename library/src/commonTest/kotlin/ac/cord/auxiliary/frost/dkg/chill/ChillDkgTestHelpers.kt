package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.TestHelpers
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.reflect.KClass
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Helpers to consume the official ChillDKG test vectors, mirroring
 * gen_vector_utils/util.py from the Python reference repository.
 */
object ChillDkgTestHelpers {

    fun readVector(filename: String): JsonObject {
        return TestHelpers.readResourceAsJson("vectors/chilldkg/$filename").jsonObject
    }

    fun hex(value: String): ByteArray = Hex.decode(value)

    fun paramsFromDict(params: JsonObject): ChillDkg.SessionParams {
        return ChillDkg.SessionParams(
            params["hostpubkeys"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) },
            params["t"]!!.jsonPrimitive.int
        )
    }

    fun assertDkgOutputEquals(expected: JsonObject, actual: DkgOutput) {
        val expectedSecshare = expected["secshare"]!!.jsonPrimitive.content.let {
            if (it == "null") null else Hex.decode(it)
        }
        if (expectedSecshare == null) {
            assertTrue(actual.secshare == null, "expected null secshare")
        } else {
            assertTrue(actual.secshare.contentEquals(expectedSecshare), "secshare mismatch")
        }
        assertTrue(actual.threshPk.contentEquals(Hex.decode(expected["threshPk"]!!.jsonPrimitive.content)), "threshPk mismatch")
        val expectedPubshares = expected["pubshares"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        assertEquals(expectedPubshares.size, actual.pubshares.size, "pubshares size mismatch")
        expectedPubshares.zip(actual.pubshares).forEach { (e, a) ->
            assertTrue(a.contentEquals(e), "pubshare mismatch")
        }
    }

    fun assertParamsEquals(expected: JsonObject, actual: ChillDkg.SessionParams) {
        val expectedHostpubkeys = expected["hostpubkeys"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        assertEquals(expectedHostpubkeys.size, actual.hostpubkeys.size)
        expectedHostpubkeys.zip(actual.hostpubkeys).forEach { (e, a) ->
            assertTrue(a.contentEquals(e), "hostpubkey mismatch")
        }
        assertEquals(expected["t"]!!.jsonPrimitive.int, actual.t)
    }

    private fun expectedErrorClass(type: String): KClass<out Throwable> {
        return when (type) {
            "ValueError" -> IllegalArgumentException::class
            "IndexError" -> IndexOutOfBoundsException::class
            "HostSeckeyError" -> ChillDkg.HostSeckeyError::class
            "SessionParamsError" -> ChillDkg.SessionParamsError::class
            "InvalidHostPubkeyError" -> ChillDkg.InvalidHostPubkeyError::class
            "DuplicateHostPubkeyError" -> ChillDkg.DuplicateHostPubkeyError::class
            "ThresholdOrCountError" -> ChillDkg.ThresholdOrCountError::class
            "RandomnessError" -> ChillDkg.RandomnessError::class
            "RecoveryDataError" -> ChillDkg.RecoveryDataError::class
            "InvalidRecoveryAckError" -> ChillDkg.InvalidRecoveryAckError::class
            "FaultyParticipantError" -> FaultyParticipantError::class
            "FaultyParticipantOrCoordinatorError" -> FaultyParticipantOrCoordinatorError::class
            "FaultyCoordinatorError" -> FaultyCoordinatorError::class
            "UnknownFaultyParticipantOrCoordinatorError" -> UnknownFaultyParticipantOrCoordinatorError::class
            else -> throw RuntimeException("Unsupported error type: $type")
        }
    }

    /**
     * Mirror of gen_vector_utils' assert_raises: the thrown exception must match
     * the expected error dict (type, participant ids, message) exactly.
     */
    fun assertRaises(expectedError: JsonObject, tryFn: () -> Any?) {
        val thrown = try {
            tryFn()
            null
        } catch (e: Exception) {
            e
        } ?: throw AssertionError("Expected exception")

        val expectedType = expectedError["type"]!!.jsonPrimitive.content
        val expectedClass = expectedErrorClass(expectedType)
        if (thrown::class != expectedClass) {
            throw AssertionError("Wrong exception raised: ${thrown::class.simpleName} (expected $expectedType)", thrown)
        }

        expectedError["participantId"]?.jsonPrimitive?.int?.let { expected ->
            val actual = when (thrown) {
                is FaultyParticipantError -> thrown.participantId
                is FaultyParticipantOrCoordinatorError -> thrown.participantId
                is ChillDkg.InvalidHostPubkeyError -> thrown.participantId
                else -> null
            }
            assertEquals(expected, actual, "participantId mismatch")
        }
        expectedError["participantId1"]?.jsonPrimitive?.int?.let { expected ->
            assertEquals(expected, (thrown as ChillDkg.DuplicateHostPubkeyError).participantId1, "participantId1 mismatch")
        }
        expectedError["participantId2"]?.jsonPrimitive?.int?.let { expected ->
            assertEquals(expected, (thrown as ChillDkg.DuplicateHostPubkeyError).participantId2, "participantId2 mismatch")
        }

        val expectedMessage = expectedError["message"]?.jsonPrimitive?.content
        assertEquals(expectedMessage, thrown.message, "exception message mismatch")
    }
}
