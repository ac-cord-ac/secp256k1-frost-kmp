package ac.cord.auxiliary.frost

import ac.cord.auxiliary.TestHelpers
import ac.cord.auxiliary.cryptography.Point
import ac.cord.auxiliary.cryptography.to32LengthByteArray
import ac.cord.auxiliary.cryptography.to8LengthByteArray
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import korlibs.crypto.SecureRandom
import kotlinx.serialization.json.*
import kotlin.reflect.KClass
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
        "invalid_contribution" -> {
            Pair(
                InvalidContributionException::class,
                { e ->
                    val invalidContributionException = e as? InvalidContributionException

                    val contrib = error["contrib"]?.jsonPrimitive?.content
                    val match = if (contrib != null) {
                        invalidContributionException?.signerId == error["signer_id"]?.jsonPrimitive?.intOrNull?.toBigInteger() && invalidContributionException?.contrib == contrib
                    } else {
                        invalidContributionException?.signerId == error["signer_id"]?.jsonPrimitive?.intOrNull?.toBigInteger()
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

fun Throwable.testThrowable(expectedException: KClass<out Throwable>, exceptionProcessor: (Throwable) -> Boolean) {
    if (this::class == expectedException) {
        assertTrue(exceptionProcessor(this))
    } else {
        throw AssertionError("Wrong exception raised in a test (expecting=${expectedException}).", this)
    }
}

class FrostTests {
    val logger = Logger.withTag("FrostTests")

    @Test
    fun `test keygen vectors`() {
        val tests = TestHelpers.readResourceAsJson("vectors/keygen_vectors.json")

        val validTestCases = tests.jsonObject["valid_test_cases"]!!.jsonArray

        for (validTestCase in validTestCases) {
            val maxParticipants = validTestCase.jsonObject["max_participants"]!!.jsonPrimitive.int
            val minParticipants = validTestCase.jsonObject["min_participants"]!!.jsonPrimitive.int
            val groupPublicKey = PublicKey(
                Hex.decode(validTestCase.jsonObject["group_public_key"]!!.jsonPrimitive.content)
            )

            val identifiers =
                validTestCase.jsonObject["participant_identifiers"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int.toBigInteger().toByteArray()
                }

            val publicShares =
                validTestCase.jsonObject["participant_pubshares"]!!.jsonArray.map { jsonElement ->
                    PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
                }
            val secretShares =
                validTestCase.jsonObject["participant_secshares"]!!.jsonArray.map { jsonElement ->
                    Hex.decode(jsonElement.jsonPrimitive.content)
                }

            assertTrue(
                Frost.checkPubSharesCorrectness(secretShares, publicShares)
            )
            assertTrue(
                Frost.checkGroupPublicKeyCorrectness(
                    maxParticipants,
                    minParticipants,
                    groupPublicKey,
                    identifiers,
                    secretShares,
                    publicShares
                )
            )
        }

        val publicShareFailureTestCases =
            tests.jsonObject["pubshare_correctness_fail_test_cases"]!!.jsonArray
        for (failureTestCase in publicShareFailureTestCases) {
            val publicShares =
                failureTestCase.jsonObject["participant_pubshares"]!!.jsonArray.map { jsonElement ->
                    PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
                }
            val secretShares =
                failureTestCase.jsonObject["participant_secshares"]!!.jsonArray.map { jsonElement ->
                    Hex.decode(jsonElement.jsonPrimitive.content)
                }

            assertFalse(
                Frost.checkPubSharesCorrectness(
                    secretShares,
                    publicShares
                )
            )
        }

        val groupPublicKeyFailureTestCases =
            tests.jsonObject["group_pubkey_correctness_fail_test_cases"]!!.jsonArray
        for (failureTestCase in groupPublicKeyFailureTestCases) {
            val maxParticipants = failureTestCase.jsonObject["max_participants"]!!.jsonPrimitive.int
            val minParticipants = failureTestCase.jsonObject["min_participants"]!!.jsonPrimitive.int
            val groupPublicKey = PublicKey(
                Hex.decode(failureTestCase.jsonObject["group_public_key"]!!.jsonPrimitive.content)
            )


            val identifiers =
                failureTestCase.jsonObject["participant_identifiers"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int.toBigInteger().toByteArray()
                }

            val publicShares =
                failureTestCase.jsonObject["participant_pubshares"]!!.jsonArray.map { jsonElement ->
                    PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
                }
            val secretShares =
                failureTestCase.jsonObject["participant_secshares"]!!.jsonArray.map { jsonElement ->
                    Hex.decode(jsonElement.jsonPrimitive.content)
                }

            assertFalse(
                Frost.checkGroupPublicKeyCorrectness(
                    maxParticipants,
                    minParticipants,
                    groupPublicKey,
                    identifiers,
                    secretShares,
                    publicShares
                )
            )
        }
    }

    @Test
    fun `test nonce gen vectors`() {
        val tests = TestHelpers.readResourceAsJson("vectors/nonce_gen_vectors.json")

        val testCases = tests.jsonObject["test_cases"]!!.jsonArray

        for (testCase in testCases) {
            logger.d(testCase.jsonObject["comment"]!!.jsonPrimitive.content)

            val rand_ = testCase.getValue("rand_")
            val secretShare = testCase.getValueOrNull("secshare")
            val publicShare = testCase.getValueOrNull("pubshare")?.let { PublicKey(it) }

            val groupPublicKey = testCase.getValueOrNull("group_pk")?.let {
                XonlyPublicKey(
                    ByteVector32(it)
                )
            }

            val message = testCase.getValueOrNull("msg")
            val extraIn = testCase.getValueOrNull("extra_in")

            val expectedSecretNonce = testCase.getValue("expected_secnonce")
            val expectedPublicNonce = testCase.getValue("expected_pubnonce")

            val actualGeneratedNonce = Frost.nonceGen(
                rand_ = rand_,
                secretShare = secretShare,
                publicShare = publicShare,
                groupPublicKey = groupPublicKey,
                messagePrefixed = message?.let {
                    byteArrayOf(0x01) +
                            message.size.to8LengthByteArray() + message
                } ?: byteArrayOf(0x00),
                extraIn = extraIn ?: byteArrayOf()
            )

            assertContentEquals(
                expectedSecretNonce,
                actualGeneratedNonce.first.getSecretNonce(),
                "Secret Nonce is incorrect"
            )
            assertContentEquals(
                expectedPublicNonce,
                actualGeneratedNonce.second.value,
                "Public nonce is incorrect"
            )
        }
    }

    @Test
    fun `test nonce agg vectors`() {
        val tests = TestHelpers.readResourceAsJson("vectors/nonce_agg_vectors.json")

        val testFrostPublicNonces = tests.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
            FrostPublicNonce(Hex.decode(jsonElement.jsonPrimitive.content))
        }

        val validTestCases = tests.jsonObject["valid_test_cases"]!!.jsonArray

        for (validTestCase in validTestCases) {
            val publicNonceIndices =
                validTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int
                }
            val publicNonces =
                testFrostPublicNonces.filterIndexed { index, _ -> publicNonceIndices.contains(index) }

            val identifiers =
                validTestCase.jsonObject["participant_identifiers"]!!.jsonArray.map { jsonElement ->
                    ByteVector32(
                        jsonElement.jsonPrimitive.int.toBigInteger().to32LengthByteArray()
                    )
                }

            val expectedAggregateNonce =
                Hex.decode(validTestCase.jsonObject["expected_aggnonce"]!!.jsonPrimitive.content)

            assertContentEquals(
                expectedAggregateNonce,
                Frost.nonceAgg(publicNonces, identifiers),
                "Aggregate nonce doesn't match"
            )
        }


        val errorTestCases = tests.jsonObject["error_test_cases"]!!.jsonArray
        for ((index, errorTestCase) in errorTestCases.withIndex()) {
            val publicNonceIndices =
                errorTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int
                }
            val publicNonces =
                testFrostPublicNonces.filterIndexed { index, _ -> publicNonceIndices.contains(index) }

            val identifiers =
                errorTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int.toBigInteger().toByteArray()
                }

//          TODO:  val exception = assertFailsWith<InvalidContributionException> {
//                Bip340.nonceAgg(publicNonces, identifiers)
//            }
        }
    }

    @Test
    fun `test sign verify vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/sign_verify_vectors.json")

        val secretShareP1 = testData.getValue("secshare_p1")
        val identifiers = testData.jsonObject["identifiers"]!!.jsonArray.map { jsonElement ->
            jsonElement.jsonPrimitive.int.toBigInteger()
        }

        val publicShares = testData.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
            PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
        }

        assertEquals(
            publicShares.first(),
            Frost.individualPublicKey(secretShareP1)
        )

        val secretNoncesBytes = testData.jsonObject["secnonces_p1"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }
        val frostPublicNonces = testData.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
            FrostPublicNonce(
                Hex.decode(jsonElement.jsonPrimitive.content)
            )
        }

        val k1 = secretNoncesBytes.first().sliceArray(0..31).toBigInteger()
        val k2 = secretNoncesBytes.first().sliceArray(32..63).toBigInteger()

        val R_s1 = Point.G.mul(k1)
        val R_s2 = Point.G.mul(k2)

        assertNotNull(R_s1)
        assertNotNull(R_s2)

        assertContentEquals(
            frostPublicNonces.first().value,
            R_s1.cbytes() + R_s2.cbytes()
        )

        val aggregateNonces = testData.jsonObject["aggnonces"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }
        val messages = testData.jsonObject["msgs"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }

        for (validTestCase in testData.jsonObject["valid_test_cases"]!!.jsonArray) {
            logger.d(validTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val identifiersTemp = validTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                ByteVector32(
                    identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                )
            }

            val pubicSharesTemp =
                validTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }
            val publicNoncesTemp =
                validTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    frostPublicNonces[jsonElement.jsonPrimitive.int]
                }

            val aggregateNonceTemp =
                aggregateNonces[validTestCase.jsonObject["aggnonce_index"]!!.jsonPrimitive.int]

            assertContentEquals(
                aggregateNonceTemp,
                Frost.nonceAgg(publicNoncesTemp, identifiersTemp)
            )

            val message = messages[validTestCase.jsonObject["msg_index"]!!.jsonPrimitive.int]
            val signerIndex = validTestCase.jsonObject["signer_index"]!!.jsonPrimitive.int
            val myIdentifier = identifiersTemp[signerIndex]
            val expected = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

            val frostSessionContext = FrostSessionContext(
                aggregateNonceTemp,
                identifiersTemp,
                pubicSharesTemp,
                listOf(),
                listOf(),
                message
            )
            val frostSecretNonceTemp = FrostSecretNonce(
                secretNoncesBytes.first()
            )

            val partialSignature = frostSessionContext.sign(
                frostSecretNonceTemp, secretShareP1, myIdentifier
            )
            assertContentEquals(
                expected,
                partialSignature.value.toByteArray(),
                "Partial signature not as expected"
            )

            assertTrue(
                Frost.partialSignatureVerify(
                    FrostPartialSignature(
                        ByteVector32( expected)
                    ),
                    identifiersTemp,
                    publicNoncesTemp,
                    pubicSharesTemp,
                    listOf(),
                    listOf(),
                    message,
                    signerIndex
                ),
                "partialSignatureVerify failed"
            )

        }

        for (signErrorTestCase in testData.jsonObject["sign_error_test_cases"]!!.jsonArray) {
            logger.d(signErrorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = signErrorTestCase.getErrorDetails("error")

            val identifiersTemp = signErrorTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                ByteVector32(
                    identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                )
            }
            val pubicSharesTemp =
                signErrorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }

            val aggregateNonceTemp =
                aggregateNonces[signErrorTestCase.jsonObject["aggnonce_index"]!!.jsonPrimitive.int]


            val message = messages[signErrorTestCase.jsonObject["msg_index"]!!.jsonPrimitive.int]

            val myIdentifier = signErrorTestCase.jsonObject["signer_index"]?.jsonPrimitive?.intOrNull?.let { signerIndex ->
                identifiersTemp[signerIndex]
            } ?: ByteVector32(
                signErrorTestCase.jsonObject["signer_id"]!!.jsonPrimitive.int.toBigInteger().to32LengthByteArray()
            )

            val frostSecretNonceTemp = FrostSecretNonce(
                secretNoncesBytes[signErrorTestCase.jsonObject["secnonce_index"]!!.jsonPrimitive.int]
            )

            val frostSessionContext = FrostSessionContext(
                aggregateNonceTemp,
                identifiersTemp,
                pubicSharesTemp,
                listOf(),
                listOf(),
                message
            )


            val throwable = assertFailsWith<Throwable> {
                frostSessionContext.sign(
                    frostSecretNonceTemp,
                    secretShareP1,
                    myIdentifier,
                )
            }

            throwable.testThrowable(
                expectedException,
                exceptionProcessor
            )
        }

        for (verifyFailTestCase in testData.jsonObject["verify_fail_test_cases"]!!.jsonArray) {
            val partialSignature = Hex.decode(verifyFailTestCase.jsonObject["psig"]!!.jsonPrimitive.content)

            val identifiersTemp = verifyFailTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                ByteVector32(
                    identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                )
            }

            val pubicSharesTemp =
                verifyFailTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }
            val publicNoncesTemp =
                verifyFailTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    frostPublicNonces[jsonElement.jsonPrimitive.int]
                }

            val message = messages[verifyFailTestCase.jsonObject["msg_index"]!!.jsonPrimitive.int]
            val signerIndex = verifyFailTestCase.jsonObject["signer_index"]!!.jsonPrimitive.int

            assertFalse(
                Frost.partialSignatureVerify(
                    FrostPartialSignature(
                        ByteVector32( partialSignature)
                    ),
                    identifiersTemp,
                    publicNoncesTemp,
                    pubicSharesTemp,
                    listOf(),
                    listOf(),
                    message,
                    signerIndex
                )
            )
        }

        for (verifyErrorTestCase in testData.jsonObject["verify_error_test_cases"]!!.jsonArray) {
            logger.d(verifyErrorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = verifyErrorTestCase.getErrorDetails("error")

            val partialSignature = Hex.decode(verifyErrorTestCase.jsonObject["psig"]!!.jsonPrimitive.content)

            val identifiersTemp = verifyErrorTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                ByteVector32(
                    identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                )
            }

            val pubicSharesTemp =
                verifyErrorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }
            val publicNoncesTemp =
                verifyErrorTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    frostPublicNonces[jsonElement.jsonPrimitive.int]
                }

            val message = messages[verifyErrorTestCase.jsonObject["msg_index"]!!.jsonPrimitive.int]
            val signerIndex = verifyErrorTestCase.jsonObject["signer_index"]!!.jsonPrimitive.int

            val throwable = assertFailsWith<Throwable> {
                Frost.partialSignatureVerify(
                    FrostPartialSignature(
                        ByteVector32( partialSignature)
                    ),
                    identifiersTemp,
                    publicNoncesTemp,
                    pubicSharesTemp,
                    listOf(),
                    listOf(),
                    message,
                    signerIndex
                )
            }

            throwable.testThrowable(
                expectedException,
                exceptionProcessor
            )
        }

    }

    @Test
    fun `test tweak vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/tweak_vectors.json")

        val secretShareP1 = testData.getValue("secshare_p1")
        val identifiers = testData.jsonObject["identifiers"]!!.jsonArray.map { jsonElement ->
            jsonElement.jsonPrimitive.int.toBigInteger()
        }

        val publicShares = testData.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
            PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
        }

        assertEquals(
            publicShares.first(),
            Frost.individualPublicKey(secretShareP1)
        )

        val secretNonceP1 =  Hex.decode(testData.jsonObject["secnonce_p1"]!!.jsonPrimitive.content)
        val frostPublicNonces = testData.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
            FrostPublicNonce(
                Hex.decode(jsonElement.jsonPrimitive.content)
            )
        }

        val k1 = secretNonceP1.sliceArray(0..31).toBigInteger()
        val k2 = secretNonceP1.sliceArray(32..63).toBigInteger()

        val R_s1 = Point.G.mul(k1)
        val R_s2 = Point.G.mul(k2)

        assertNotNull(R_s1)
        assertNotNull(R_s2)

        assertContentEquals(
            frostPublicNonces.first().value,
            R_s1.cbytes() + R_s2.cbytes()
        )

        val aggregateNonces = testData.jsonObject["aggnonces"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }
        val tweaks = testData.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }

        val message = Hex.decode(testData.jsonObject["msg"]!!.jsonPrimitive.content)

        for (validTestCase in testData.jsonObject["valid_test_cases"]!!.jsonArray) {
            logger.d(validTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")
            val identifiersTemp =
                validTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                    ByteVector32(
                        identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                    )
                }
            val pubicSharesTemp =
                validTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }
            val publicNoncesTemp =
                validTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    frostPublicNonces[jsonElement.jsonPrimitive.int]
                }

            val aggregateNonceTemp =
                aggregateNonces[validTestCase.jsonObject["aggnonce_index"]!!.jsonPrimitive.int]

            assertContentEquals(
                aggregateNonceTemp,
                Frost.nonceAgg(publicNoncesTemp, identifiersTemp)
            )

            val tweaksTemp = validTestCase.jsonObject["tweak_indices"]!!.jsonArray.map { jsonElement ->
                tweaks[jsonElement.jsonPrimitive.int]
            }
            val tweakModesTemp = validTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.boolean
            }

            val signerIndex = validTestCase.jsonObject["signer_index"]!!.jsonPrimitive.int
            val myIdentifier = identifiersTemp[signerIndex]

            val expected = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

            val frostSessionContext = FrostSessionContext(
                aggregateNonceTemp,
                identifiersTemp,
                pubicSharesTemp,
                tweaksTemp,
                tweakModesTemp,
                message
            )

            val frostSecretNonceTemp = FrostSecretNonce(
                secretNonceP1
            )

            val partialSignature = frostSessionContext.sign(
                frostSecretNonceTemp, secretShareP1, myIdentifier
            )
            assertContentEquals(
                expected,
                partialSignature.value.toByteArray(),
                "Partial signature not as expected"
            )

            assertTrue(
                Frost.partialSignatureVerify(
                    FrostPartialSignature(
                        ByteVector32( expected)
                    ),
                    identifiersTemp,
                    publicNoncesTemp,
                    pubicSharesTemp,
                    tweaksTemp,
                    tweakModesTemp,
                    message,
                    signerIndex
                ),
                "partialSignatureVerify failed"
            )
        }

        for (errorTestCase in testData.jsonObject["error_test_cases"]!!.jsonArray) {
            logger.d(errorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = errorTestCase.getErrorDetails("error")

            val identifiersTemp =
                errorTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                    ByteVector32(
                        identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                    )
                }
            val pubicSharesTemp =
                errorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }

            val aggregateNonceTemp =
                aggregateNonces[errorTestCase.jsonObject["aggnonce_index"]!!.jsonPrimitive.int]

            val tweaksTemp = errorTestCase.jsonObject["tweak_indices"]!!.jsonArray.map { jsonElement ->
                tweaks[jsonElement.jsonPrimitive.int]
            }
            val tweakModesTemp = errorTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.boolean
            }

            val signerIndex = errorTestCase.jsonObject["signer_index"]!!.jsonPrimitive.int
            val myIdentifier = identifiersTemp[signerIndex]

            val frostSessionContext = FrostSessionContext(
                aggregateNonceTemp,
                identifiersTemp,
                pubicSharesTemp,
                tweaksTemp,
                tweakModesTemp,
                message
            )

            val throwable = assertFailsWith<Throwable> {
                frostSessionContext.sign(
                    FrostSecretNonce(secretNonceP1),
                    secretShareP1,
                    myIdentifier,
                )
            }

            throwable.testThrowable(
                expectedException,
                exceptionProcessor
            )
        }
    }

    @Test
    fun `test sig agg vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/sig_agg_vectors.json")

        val identifiers = testData.jsonObject["identifiers"]!!.jsonArray.map { jsonElement ->
            jsonElement.jsonPrimitive.int.toBigInteger()
        }

        val publicShares = testData.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
            PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
        }

        val frostPublicNonces = testData.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
            FrostPublicNonce(
                Hex.decode(jsonElement.jsonPrimitive.content)
            )
        }

        val tweaks = testData.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }
        val partialSignatures = testData.jsonObject["psigs"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }
        val message = Hex.decode(testData.jsonObject["msg"]!!.jsonPrimitive.content)

        for (validTestCase in testData.jsonObject["valid_test_cases"]!!.jsonArray) {
            val identifiersTemp =
                validTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                    ByteVector32(
                        identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                    )
                }
            val pubicSharesTemp =
                validTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }
            val publicNoncesTemp =
                validTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    frostPublicNonces[jsonElement.jsonPrimitive.int]
                }

            val aggregateNonceTemp = Hex.decode(validTestCase.jsonObject["aggnonce"]!!.jsonPrimitive.content)

            assertContentEquals(
                aggregateNonceTemp,
                Frost.nonceAgg(publicNoncesTemp, identifiersTemp)
            )

            val tweaksTemp = validTestCase.jsonObject["tweak_indices"]!!.jsonArray.map { jsonElement ->
                tweaks[jsonElement.jsonPrimitive.int]
            }
            val tweakModesTemp = validTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.boolean
            }

            val partialSignaturesTemp = validTestCase.jsonObject["psig_indices"]!!.jsonArray.map { jsonElement ->
                partialSignatures[jsonElement.jsonPrimitive.int]
            }

            val expected = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

            val frostSessionContext = FrostSessionContext(
                aggregateNonceTemp,
                identifiersTemp,
                pubicSharesTemp,
                tweaksTemp,
                tweakModesTemp,
                message
            )

            val signature = frostSessionContext.partialSignatureAggregate(
                partialSignaturesTemp,
                identifiersTemp
            )

            assertContentEquals(
                expected,
                signature
            )
            val tweakContext = Frost.groupPublicKeyAndTweet(
                pubicSharesTemp,
                identifiersTemp,
                tweaksTemp,
                tweakModesTemp
            )
            val tweakedGroupPublicKey = tweakContext.getXonlyPublicKey()

            assertTrue(
                Secp256k1.verifySchnorr(
                    pub = tweakedGroupPublicKey.value.toByteArray(),
                    data = message,
                    signature = signature,
                ),
                "Schnorr signature verification failure"
            )
        }

        for (errorTestCase in testData.jsonObject["error_test_cases"]!!.jsonArray) {
            logger.d(errorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = errorTestCase.getErrorDetails("error")

            val identifiersTemp =
                errorTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                    ByteVector32(
                        identifiers[jsonElement.jsonPrimitive.int].to32LengthByteArray()
                    )
                }
            val pubicSharesTemp =
                errorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                    publicShares[jsonElement.jsonPrimitive.int]
                }

            val aggregateNonceTemp = Hex.decode(
                errorTestCase.jsonObject["aggnonce"]!!.jsonPrimitive.content
            )

            val tweaksTemp = errorTestCase.jsonObject["tweak_indices"]!!.jsonArray.map { jsonElement ->
                tweaks[jsonElement.jsonPrimitive.int]
            }
            val tweakModesTemp = errorTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.boolean
            }

            val partialSignaturesTemp = errorTestCase.jsonObject["psig_indices"]!!.jsonArray.map { jsonElement ->
                partialSignatures[jsonElement.jsonPrimitive.int]
            }

            val frostSessionContext = FrostSessionContext(
                aggregateNonceTemp,
                identifiersTemp,
                pubicSharesTemp,
                tweaksTemp,
                tweakModesTemp,
                message
            )

            val throwable = assertFailsWith<Throwable> {
                frostSessionContext.partialSignatureAggregate(
                    partialSignaturesTemp,
                    identifiersTemp,
                )
            }

            throwable.testThrowable(
                expectedException,
                exceptionProcessor
            )
        }
    }


    @Test
    fun `test sign and verify random`() {
        val maxParticipants = SecureRandom.nextInt(2, 11)
        val minParticipants = SecureRandom.nextInt(2, maxParticipants+1)


        // TODO: test_sign_and_verify_random
    }
}