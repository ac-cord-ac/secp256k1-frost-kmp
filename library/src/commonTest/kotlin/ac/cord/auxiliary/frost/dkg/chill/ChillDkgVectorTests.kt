package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.frost.dkg.chill.ChillDkgTestHelpers.assertDkgOutputEquals
import ac.cord.auxiliary.frost.dkg.chill.ChillDkgTestHelpers.assertParamsEquals
import ac.cord.auxiliary.frost.dkg.chill.ChillDkgTestHelpers.assertRaises
import ac.cord.auxiliary.frost.dkg.chill.ChillDkgTestHelpers.hex
import ac.cord.auxiliary.frost.dkg.chill.ChillDkgTestHelpers.paramsFromDict
import ac.cord.auxiliary.frost.dkg.chill.ChillDkgTestHelpers.readVector
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of the vector-based tests of the Python reference's tests.py. Consumes
 * the official vectors from resources/vectors/chilldkg/.
 */
class ChillDkgVectorTests {

    @Test
    fun `test hostpubkey gen vectors`() {
        val testData = readVector("hostpubkey_gen_vectors.json")

        val validTestCases = testData["validTestCases"]!!.jsonArray
        val errorTestCases = testData["errorTestCases"]!!.jsonArray
        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, validTestCases.size + errorTestCases.size)

        for (testCase in validTestCases) {
            val tc = testCase.jsonObject
            val hostseckey = hex(tc["hostseckey"]!!.jsonPrimitive.content)
            val expectedHostpubkey = hex(tc["expectedHostpubkey"]!!.jsonPrimitive.content)
            assertTrue(expectedHostpubkey.contentEquals(ChillDkg.hostpubkeyGen(hostseckey)))
        }

        for (testCase in errorTestCases) {
            val tc = testCase.jsonObject
            val hostseckey = hex(tc["hostseckey"]!!.jsonPrimitive.content)
            val expectedError = tc["expectedError"]!!.jsonObject
            assertRaises(expectedError) { ChillDkg.hostpubkeyGen(hostseckey) }
        }
    }

    @Test
    fun `test params hash vectors`() {
        val testData = readVector("params_hash_vectors.json")

        val validTestCases = testData["validTestCases"]!!.jsonArray
        val errorTestCases = testData["errorTestCases"]!!.jsonArray
        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, validTestCases.size + errorTestCases.size)

        for (testCase in validTestCases) {
            val tc = testCase.jsonObject
            val params = paramsFromDict(tc["params"]!!.jsonObject)
            val expectedHash = hex(tc["expectedParamsHash"]!!.jsonPrimitive.content)
            assertTrue(expectedHash.contentEquals(ChillDkg.paramsHash(params)))
        }

        for (testCase in errorTestCases) {
            val tc = testCase.jsonObject
            val params = paramsFromDict(tc["params"]!!.jsonObject)
            val expectedError = tc["expectedError"]!!.jsonObject
            assertRaises(expectedError) { ChillDkg.paramsHash(params) }
        }
    }

    @Test
    fun `test participant step1 vectors`() {
        val testData = readVector("participant_step1_vectors.json")

        var totalCases = 0
        for (group in testData["testGroups"]!!.jsonArray) {
            val g = group.jsonObject
            for (testCase in g["validTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val hostseckey = hex(tc["hostseckey"]!!.jsonPrimitive.content)
                val params = paramsFromDict(tc["params"]!!.jsonObject)
                val random = hex(tc["random"]!!.jsonPrimitive.content)
                val expectedPmsg1 = hex(tc["expectedPmsg1"]!!.jsonPrimitive.content)
                val (_, pmsg1) = ChillDkg.participantStep1(hostseckey, params, random)
                assertTrue(expectedPmsg1.contentEquals(pmsg1))
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }

            for (testCase in g["errorTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val hostseckey = hex(tc["hostseckey"]!!.jsonPrimitive.content)
                val params = paramsFromDict(tc["params"]!!.jsonObject)
                val random = hex(tc["random"]!!.jsonPrimitive.content)
                val expectedError = tc["expectedError"]!!.jsonObject
                assertRaises(expectedError) { ChillDkg.participantStep1(hostseckey, params, random) }
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }
        }

        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, totalCases)
    }

    @Test
    fun `test participant step2 vectors`() {
        val testData = readVector("participant_step2_vectors.json")

        var totalCases = 0
        for (group in testData["testGroups"]!!.jsonArray) {
            val g = group.jsonObject
            // common fields for all test cases
            val params = paramsFromDict(g["params"]!!.jsonObject)
            val hostseckey = hex(g["hostseckey"]!!.jsonPrimitive.content)
            val random = hex(g["random"]!!.jsonPrimitive.content)
            val auxRand = hex(g["auxRand"]!!.jsonPrimitive.content)

            val (state1, pmsg1) = ChillDkg.participantStep1(hostseckey, params, random)
            assertTrue(hex(g["pmsg1"]!!.jsonPrimitive.content).contentEquals(pmsg1)) // checkpoint

            for (testCase in g["validTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val cmsg1 = hex(tc["cmsg1"]!!.jsonPrimitive.content)
                val expectedPmsg2 = hex(tc["expectedPmsg2"]!!.jsonPrimitive.content)
                val (_, pmsg2) = ChillDkg.participantStep2(hostseckey, state1, cmsg1, auxRand)
                assertTrue(expectedPmsg2.contentEquals(pmsg2))
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }

            for (testCase in g["errorTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val caseHostseckey = hex(tc["hostseckey"]?.jsonPrimitive?.content ?: g["hostseckey"]!!.jsonPrimitive.content)
                val caseAuxRand = hex(tc["auxRand"]?.jsonPrimitive?.content ?: g["auxRand"]!!.jsonPrimitive.content)
                val cmsg1 = hex(tc["cmsg1"]!!.jsonPrimitive.content)
                val expectedError = tc["expectedError"]!!.jsonObject
                assertRaises(expectedError) {
                    ChillDkg.participantStep2(caseHostseckey, state1, cmsg1, caseAuxRand)
                }
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }
        }

        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, totalCases)
    }

    @Test
    fun `test participant finalize vectors`() {
        val testData = readVector("participant_finalize_vectors.json")

        var totalCases = 0
        for (group in testData["testGroups"]!!.jsonArray) {
            val g = group.jsonObject
            // common fields for all test cases
            val params = paramsFromDict(g["params"]!!.jsonObject)
            val hostseckey = hex(g["hostseckey"]!!.jsonPrimitive.content)
            val random = hex(g["random"]!!.jsonPrimitive.content)
            val auxRand = hex(g["auxRand"]!!.jsonPrimitive.content)

            // compute state1 and assert pmsg1
            val (state1, pmsg1) = ChillDkg.participantStep1(hostseckey, params, random)
            assertTrue(hex(g["pmsg1"]!!.jsonPrimitive.content).contentEquals(pmsg1))
            // compute state2 and assert pmsg2
            val cmsg1 = hex(g["cmsg1"]!!.jsonPrimitive.content)
            val (state2, pmsg2) = ChillDkg.participantStep2(hostseckey, state1, cmsg1, auxRand)
            assertTrue(hex(g["pmsg2"]!!.jsonPrimitive.content).contentEquals(pmsg2))

            for (testCase in g["validTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val cmsg2 = hex(tc["cmsg2"]!!.jsonPrimitive.content)
                val (pout, prec) = ChillDkg.participantFinalize(state2, cmsg2)
                val expectedPout = tc["expectedOutput"]!!.jsonObject["dkgOutput"]!!.jsonObject
                val expectedPrec = hex(tc["expectedOutput"]!!.jsonObject["recoveryData"]!!.jsonPrimitive.content)
                assertDkgOutputEquals(expectedPout, pout)
                assertTrue(expectedPrec.contentEquals(prec))
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }

            for (testCase in g["errorTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val cmsg2 = hex(tc["cmsg2"]!!.jsonPrimitive.content)
                val expectedError = tc["expectedError"]!!.jsonObject
                assertRaises(expectedError) { ChillDkg.participantFinalize(state2, cmsg2) }
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }
        }

        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, totalCases)
    }

    @Test
    fun `test participant investigate vectors`() {
        val testData = readVector("participant_investigate_vectors.json")

        var totalCases = 0
        for (group in testData["testGroups"]!!.jsonArray) {
            val g = group.jsonObject
            // common fields for all test cases
            val params = paramsFromDict(g["params"]!!.jsonObject)
            val hostseckey = hex(g["hostseckey"]!!.jsonPrimitive.content)
            val random = hex(g["random"]!!.jsonPrimitive.content)
            val auxRand = hex(g["auxRand"]!!.jsonPrimitive.content)
            val cmsg1Pool = g["cmsg1Pool"]!!.jsonArray

            // Re-derive state1
            val (state1, pmsg1) = ChillDkg.participantStep1(hostseckey, params, random)
            assertTrue(hex(g["pmsg1"]!!.jsonPrimitive.content).contentEquals(pmsg1))

            for (testCase in g["errorTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val cmsg1 = hex(cmsg1Pool[tc["cmsg1Index"]!!.jsonPrimitive.int].jsonPrimitive.content)
                val cinvMsg = hex(tc["cinvMsg"]!!.jsonPrimitive.content)
                val expectedError = tc["expectedError"]!!.jsonObject
                try {
                    ChillDkg.participantStep2(hostseckey, state1, cmsg1, auxRand)
                    throw AssertionError("Expected exception")
                } catch (e: UnknownFaultyParticipantOrCoordinatorError) {
                    assertRaises(expectedError) { ChillDkg.participantInvestigate(e, cinvMsg) }
                } catch (e: Exception) {
                    throw AssertionError("Wrong exception raised: ${e::class.simpleName}", e)
                }
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }
        }

        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, totalCases)
    }

    @Test
    fun `test coordinator step1 vectors`() {
        val testData = readVector("coordinator_step1_vectors.json")

        var totalCases = 0
        for (group in testData["testGroups"]!!.jsonArray) {
            val g = group.jsonObject
            val pmsg1Pool = g["pmsg1Pool"]!!.jsonArray

            for (testCase in g["validTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val pmsgs1 = tc["pmsg1Indices"]!!.jsonArray.map {
                    hex(pmsg1Pool[it.jsonPrimitive.int].jsonPrimitive.content)
                }
                val params = paramsFromDict(tc["params"]!!.jsonObject)
                val expectedCmsg1 = tc["expectedCmsg1"]!!.jsonPrimitive.content
                val (_, cmsg1) = ChillDkg.coordinatorStep1(pmsgs1, params)
                assertTrue(hex(expectedCmsg1).contentEquals(cmsg1))
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }

            for (testCase in g["errorTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val pmsgs1 = tc["pmsg1Indices"]!!.jsonArray.map {
                    hex(pmsg1Pool[it.jsonPrimitive.int].jsonPrimitive.content)
                }
                val params = paramsFromDict(tc["params"]!!.jsonObject)
                val expectedError = tc["expectedError"]!!.jsonObject
                assertRaises(expectedError) { ChillDkg.coordinatorStep1(pmsgs1, params) }
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }
        }

        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, totalCases)
    }

    @Test
    fun `test coordinator finalize vectors`() {
        val testData = readVector("coordinator_finalize_vectors.json")

        var totalCases = 0

        for (group in testData["testGroups"]!!.jsonArray) {
            val g = group.jsonObject
            val params = paramsFromDict(g["params"]!!.jsonObject)
            val pmsgs1 = g["pmsgs1"]!!.jsonArray.map { hex(it.jsonPrimitive.content) }
            val pmsg2Pool = g["pmsg2Pool"]!!.jsonArray

            val (state, cmsg1) = ChillDkg.coordinatorStep1(pmsgs1, params)
            assertTrue(hex(g["cmsg1"]!!.jsonPrimitive.content).contentEquals(cmsg1))

            for (testCase in g["validTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val pmsgs2 = tc["pmsg2Indices"]!!.jsonArray.map {
                    hex(pmsg2Pool[it.jsonPrimitive.int].jsonPrimitive.content)
                }
                val (cmsg2, cout, crec) = ChillDkg.coordinatorFinalize(state, pmsgs2)
                val expectedCmsg2 = tc["expectedOutput"]!!.jsonObject["cmsg2"]!!.jsonPrimitive.content
                val expectedCout = tc["expectedOutput"]!!.jsonObject["dkgOutput"]!!.jsonObject
                val expectedCrec = tc["expectedOutput"]!!.jsonObject["recoveryData"]!!.jsonPrimitive.content
                assertTrue(hex(expectedCmsg2).contentEquals(cmsg2))
                assertDkgOutputEquals(expectedCout, cout)
                assertTrue(hex(expectedCrec).contentEquals(crec))
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }

            for (testCase in g["errorTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val pmsgs2 = tc["pmsg2Indices"]!!.jsonArray.map {
                    hex(pmsg2Pool[it.jsonPrimitive.int].jsonPrimitive.content)
                }
                val expectedError = tc["expectedError"]!!.jsonObject
                assertRaises(expectedError) { ChillDkg.coordinatorFinalize(state, pmsgs2) }
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }
        }

        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, totalCases)
    }

    @Test
    fun `test coordinator investigate vectors`() {
        val testData = readVector("coordinator_investigate_vectors.json")

        var totalCases = 0

        for (group in testData["testGroups"]!!.jsonArray) {
            val g = group.jsonObject
            val params = paramsFromDict(g["params"]!!.jsonObject)
            val pmsgs1 = g["pmsgs1"]!!.jsonArray.map { hex(it.jsonPrimitive.content) }

            for (testCase in g["validTestCases"]!!.jsonArray) {
                val tc = testCase.jsonObject
                val cinvMsgs = ChillDkg.coordinatorInvestigate(pmsgs1, params)
                val expectedCinvMsgs = tc["expectedCinvMsgs"]!!.jsonArray
                assertEquals(expectedCinvMsgs.size, cinvMsgs.size)
                expectedCinvMsgs.zip(cinvMsgs).forEach { (expected, actual) ->
                    assertTrue(hex(expected.jsonPrimitive.content).contentEquals(actual))
                }
                totalCases += 1
                assertEquals(tc["tcId"]!!.jsonPrimitive.int, totalCases)
            }
        }

        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, totalCases)
    }

    @Test
    fun `test recover vectors`() {
        val testData = readVector("recover_vectors.json")

        val validTestCases = testData["validTestCases"]!!.jsonArray
        val errorTestCases = testData["errorTestCases"]!!.jsonArray
        assertEquals(testData["totalTests"]!!.jsonPrimitive.int, validTestCases.size + errorTestCases.size)

        for (testCase in validTestCases) {
            val tc = testCase.jsonObject
            val hostseckey = tc["hostseckey"]!!.jsonPrimitive.content.let {
                if (it == "" || it == "null") null else hex(it)
            }
            val recoveryData = hex(tc["recoveryData"]!!.jsonPrimitive.content)
            val (out, params) = if (hostseckey == null) {
                ChillDkg.coordinatorRecover(recoveryData)
            } else {
                ChillDkg.participantRecover(hostseckey, recoveryData)
            }
            val expectedOut = tc["expectedOutput"]!!.jsonObject["dkgOutput"]!!.jsonObject
            val expectedParams = tc["expectedOutput"]!!.jsonObject["params"]!!.jsonObject
            assertDkgOutputEquals(expectedOut, out)
            assertParamsEquals(expectedParams, params)
        }

        for (testCase in errorTestCases) {
            val tc = testCase.jsonObject
            val hostseckey = tc["hostseckey"]!!.jsonPrimitive.content.let {
                if (it == "" || it == "null") null else hex(it)
            }
            val recoveryData = hex(tc["recoveryData"]!!.jsonPrimitive.content)
            val expectedError = tc["expectedError"]!!.jsonObject
            if (hostseckey == null) {
                assertRaises(expectedError) { ChillDkg.coordinatorRecover(recoveryData) }
            } else {
                assertRaises(expectedError) { ChillDkg.participantRecover(hostseckey, recoveryData) }
            }
        }
    }
}
