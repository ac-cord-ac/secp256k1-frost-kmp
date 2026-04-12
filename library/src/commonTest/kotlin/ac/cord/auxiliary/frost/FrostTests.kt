package ac.cord.auxiliary.frost

import ac.cord.auxiliary.TestHelpers
import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.to32LengthByteArray
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.exceptions.InvalidContributionException
import ac.cord.auxiliary.extensions.getErrorDetails
import ac.cord.auxiliary.extensions.getValue
import ac.cord.auxiliary.extensions.getValueOrNull
import ac.cord.auxiliary.extensions.testThrowable
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import korlibs.crypto.SecureRandom
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue




class FrostTests {
    val logger = Logger.withTag("FrostTests")

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
                    jsonElement.jsonPrimitive.int
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
                    jsonElement.jsonPrimitive.int
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

            val groupPublicKey = testCase.getValueOrNull("threshold_pubkey")?.let {
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
                message = message,
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
            val publicNonces =
                validTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    testFrostPublicNonces[jsonElement.jsonPrimitive.int]
                }

            val expectedAggregateNonce =
                Hex.decode(validTestCase.jsonObject["expected_aggnonce"]!!.jsonPrimitive.content)

            assertContentEquals(
                expectedAggregateNonce,
                Frost.nonceAgg(publicNonces),
                "Aggregate nonce doesn't match"
            )
        }


        val errorTestCases = tests.jsonObject["error_test_cases"]!!.jsonArray
        for (errorTestCase in errorTestCases) {
            logger.d(errorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = errorTestCase.getErrorDetails("error")

            val publicNonces =
                errorTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    testFrostPublicNonces[jsonElement.jsonPrimitive.int]
                }


            val throwable = assertFailsWith<InvalidContributionException> {
                Frost.nonceAgg(publicNonces)
            }

            throwable.testThrowable(
                expectedException,
                exceptionProcessor
            )
        }
    }

    @Test
    fun `test sign verify vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/sign_verify_vectors.json")

        val n = testData.jsonObject["n"]!!.jsonPrimitive.int
        val t = testData.jsonObject["t"]!!.jsonPrimitive.int

        val secretShareP0 = testData.getValue("secshare_p0")
        val identifiers = testData.jsonObject["identifiers"]!!.jsonArray.map { jsonElement ->
            jsonElement.jsonPrimitive.int
        }

        val publicShares = testData.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
            PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
        }

        assertEquals(
            publicShares.first(),
            Frost.individualPublicKey(secretShareP0)
        )


        val groupPublicKey = PublicKey(
            testData.getValue("threshold_pubkey")
        )

        val secretNoncesBytes = testData.jsonObject["secnonces_p0"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }
        val frostPublicNonces = testData.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
            FrostPublicNonce(
                Hex.decode(jsonElement.jsonPrimitive.content)
            )
        }

        val k1 = secretNoncesBytes.first().sliceArray(0..31).toBigInteger()
        val k2 = secretNoncesBytes.first().sliceArray(32..63).toBigInteger()

        val R_s1 = GroupElement.GENERATOR_POINT.mul(k1)
        val R_s2 = GroupElement.GENERATOR_POINT.mul(k2)

        assertNotNull(R_s1)
        assertNotNull(R_s2)

        assertContentEquals(
            frostPublicNonces.first().value,
            R_s1.toCompressedBytes().value.toByteArray() + R_s2.toCompressedBytes().value.toByteArray()
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
                identifiers[jsonElement.jsonPrimitive.int]
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
                Frost.nonceAgg(publicNoncesTemp)
            )

            val message = messages[validTestCase.jsonObject["msg_index"]!!.jsonPrimitive.int]
            val signerIndex = validTestCase.jsonObject["signer_index"]!!.jsonPrimitive.int
            val myIdentifier = identifiersTemp[signerIndex]
            val expectedPartialSignature = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

            val frostSignersContext = FrostSignersContext(
                n = n,
                t = t,
                identifiers = identifiersTemp,
                publicShares = pubicSharesTemp,
                groupPublicKey = groupPublicKey
            )
            val frostSessionContext = FrostSessionContext(
                frostSignersContext = frostSignersContext,
                aggNonce = aggregateNonceTemp,
                tweaks = listOf(),
                isXonlies = listOf(),
                message = message
            )
            val frostSecretNonceTemp = FrostSecretNonce(
                secretNoncesBytes.first()
            )

            val partialSignature = frostSessionContext.sign(
                frostSecretNonceTemp, secretShareP0, myIdentifier
            )
            assertContentEquals(
                expectedPartialSignature,
                partialSignature.value.toByteArray(),
                "Partial signature not as expected"
            )

            assertTrue(
                Frost.partialSignatureVerify(
                    frostSignersContext = frostSignersContext,
                    frostPartialSignature = FrostPartialSignature(
                        ByteVector32( expectedPartialSignature)
                    ),
                    frostPublicNonces = publicNoncesTemp,
                    tweaks = listOf(),
                    isXonlies = listOf(),
                    message = message,
                    index = signerIndex
                ),
                "partialSignatureVerify failed"
            )
        }

        for (signErrorTestCase in testData.jsonObject["sign_error_test_cases"]!!.jsonArray) {
            logger.d(signErrorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = signErrorTestCase.getErrorDetails("error")

            val identifiersTemp = signErrorTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                identifiers[jsonElement.jsonPrimitive.int]
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
            } ?: signErrorTestCase.jsonObject["signer_id"]!!.jsonPrimitive.int

            val frostSecretNonceTemp = FrostSecretNonce(
                secretNoncesBytes[signErrorTestCase.jsonObject["secnonce_index"]!!.jsonPrimitive.int]
            )
            val frostSessionContext = FrostSessionContext(
                frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    groupPublicKey = groupPublicKey
                ),
                aggregateNonceTemp,
                listOf(),
                listOf(),
                message
            )


            val throwable = assertFailsWith<Throwable> {
                frostSessionContext.sign(
                    frostSecretNonceTemp,
                    secretShareP0,
                    myIdentifier,
                )
            }

            throwable.testThrowable(
                expectedException,
                exceptionProcessor
            )
        }

        for (verifyFailTestCase in testData.jsonObject["verify_fail_test_cases"]!!.jsonArray) {
            logger.d(verifyFailTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")
            val partialSignature = Hex.decode(verifyFailTestCase.jsonObject["psig"]!!.jsonPrimitive.content)

            val identifiersTemp = verifyFailTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                identifiers[jsonElement.jsonPrimitive.int]
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
                    frostPartialSignature = FrostPartialSignature(
                        ByteVector32( partialSignature)
                    ),
                    frostPublicNonces = publicNoncesTemp,
                    frostSignersContext = FrostSignersContext(
                        n = n,
                        t = t,
                        identifiers = identifiersTemp,
                        publicShares = pubicSharesTemp,
                        groupPublicKey = groupPublicKey
                    ),
                    tweaks = listOf(),
                    isXonlies = listOf(),
                    message = message,
                    index = signerIndex
                )
            )
        }

        for (verifyErrorTestCase in testData.jsonObject["verify_error_test_cases"]!!.jsonArray) {
            logger.d(verifyErrorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = verifyErrorTestCase.getErrorDetails("error")

            val partialSignature = Hex.decode(verifyErrorTestCase.jsonObject["psig"]!!.jsonPrimitive.content)

            val identifiersTemp = verifyErrorTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                identifiers[jsonElement.jsonPrimitive.int]
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
                    frostPartialSignature = FrostPartialSignature(
                        ByteVector32( partialSignature)
                    ),
                    frostPublicNonces = publicNoncesTemp,
                    frostSignersContext = FrostSignersContext(
                        n = n,
                        t = t,
                        identifiers = identifiersTemp,
                        publicShares = pubicSharesTemp,
                        groupPublicKey = groupPublicKey
                    ),
                    tweaks = listOf(),
                    isXonlies = listOf(),
                    message = message,
                    index = signerIndex
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

        val n = testData.jsonObject["n"]!!.jsonPrimitive.int
        val t = testData.jsonObject["t"]!!.jsonPrimitive.int

        val secretShareP1 = testData.getValue("secshare_p0")
        val identifiers = testData.jsonObject["identifiers"]!!.jsonArray.map { jsonElement ->
            jsonElement.jsonPrimitive.int
        }

        val publicShares = testData.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
            PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
        }

        assertEquals(
            publicShares.first(),
            Frost.individualPublicKey(secretShareP1)
        )

        val groupPublicKey = PublicKey(
            testData.getValue("threshold_pubkey")
        )

        val secretNonceP1 =  Hex.decode(testData.jsonObject["secnonce_p0"]!!.jsonPrimitive.content)
        val frostPublicNonces = testData.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
            FrostPublicNonce(
                Hex.decode(jsonElement.jsonPrimitive.content)
            )
        }

        val k1 = secretNonceP1.sliceArray(0..31).toBigInteger()
        val k2 = secretNonceP1.sliceArray(32..63).toBigInteger()

        val R_s1 = GroupElement.GENERATOR_POINT.mul(k1)
        val R_s2 = GroupElement.GENERATOR_POINT.mul(k2)

        assertFalse { R_s1.isInfinity }
        assertFalse { R_s2.isInfinity }

        assertContentEquals(
            frostPublicNonces.first().value,
            R_s1.toCompressedBytes().value.toByteArray() + R_s2.toCompressedBytes().value.toByteArray()
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
                    identifiers[jsonElement.jsonPrimitive.int]
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
                Frost.nonceAgg(publicNoncesTemp)
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
                frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    groupPublicKey = groupPublicKey
                ),
                aggregateNonceTemp,
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
                    frostPartialSignature = FrostPartialSignature(
                        ByteVector32( expected)
                    ),
                    frostPublicNonces = publicNoncesTemp,
                    frostSignersContext = FrostSignersContext(
                        n = n,
                        t = t,
                        identifiers = identifiersTemp,
                        publicShares = pubicSharesTemp,
                        groupPublicKey = groupPublicKey
                    ),
                    tweaks = tweaksTemp,
                    isXonlies = tweakModesTemp,
                    message = message,
                    index = signerIndex
                ),
                "partialSignatureVerify failed"
            )
        }

        for (errorTestCase in testData.jsonObject["error_test_cases"]!!.jsonArray) {
            logger.d(errorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

            val (expectedException, exceptionProcessor) = errorTestCase.getErrorDetails("error")

            val identifiersTemp =
                errorTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                    identifiers[jsonElement.jsonPrimitive.int]
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

            val frostSessionContext = FrostSessionContext(frostSignersContext = FrostSignersContext(
                n = n,
                t = t,
                identifiers = identifiersTemp,
                publicShares = pubicSharesTemp,
                groupPublicKey = groupPublicKey
            ),
                aggregateNonceTemp,
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

        val n = testData.jsonObject["n"]!!.jsonPrimitive.int
        val t = testData.jsonObject["t"]!!.jsonPrimitive.int

        val identifiers = testData.jsonObject["identifiers"]!!.jsonArray.map { jsonElement ->
            jsonElement.jsonPrimitive.int
        }

        val publicShares = testData.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
            PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
        }

        val groupPublicKey = PublicKey(
            testData.getValue("threshold_pubkey")
        )

        val frostPublicNonces = testData.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
            FrostPublicNonce(
                Hex.decode(jsonElement.jsonPrimitive.content)
            )
        }

        val tweaks = testData.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
            Hex.decode(jsonElement.jsonPrimitive.content)
        }

        val message = Hex.decode(testData.jsonObject["msg"]!!.jsonPrimitive.content)

        for (validTestCase in testData.jsonObject["valid_test_cases"]!!.jsonArray) {
            val identifiersTemp =
                validTestCase.jsonObject["id_indices"]!!.jsonArray.map { jsonElement ->
                    identifiers[jsonElement.jsonPrimitive.int]
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
                Frost.nonceAgg(publicNoncesTemp)
            )

            val tweaksTemp = validTestCase.jsonObject["tweak_indices"]!!.jsonArray.map { jsonElement ->
                tweaks[jsonElement.jsonPrimitive.int]
            }
            val tweakModesTemp = validTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.boolean
            }

            val partialSignaturesTemp = validTestCase.jsonObject["psigs"]!!.jsonArray.map { jsonElement ->
                Hex.decode(jsonElement.jsonPrimitive.content)
            }

            val expected = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

            val frostSessionContext = FrostSessionContext(
                frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    groupPublicKey = groupPublicKey
                ),
                aggregateNonceTemp,
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
                    identifiers[jsonElement.jsonPrimitive.int]
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

            val partialSignaturesTemp = errorTestCase.jsonObject["psigs"]!!.jsonArray.map { jsonElement ->
                Hex.decode(jsonElement.jsonPrimitive.content)
            }

            val frostSessionContext = FrostSessionContext(
                frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    groupPublicKey = groupPublicKey
                ),
                aggregateNonceTemp,
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