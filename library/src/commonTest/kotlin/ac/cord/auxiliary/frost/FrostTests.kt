package ac.cord.auxiliary.frost

import ac.cord.auxiliary.TestHelpers
import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.exceptions.InvalidContributionException
import ac.cord.auxiliary.extensions.getErrorDetails
import ac.cord.auxiliary.extensions.getValue
import ac.cord.auxiliary.extensions.getValueOrNull
import ac.cord.auxiliary.extensions.testThrowable
import co.touchlab.kermit.Logger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
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

    @Test
    fun `test nonce gen vectors`() {
        val tests = TestHelpers.readResourceAsJson("vectors/nonce_gen_vectors.json")

        val testCases = tests.jsonObject["valid_tests"]!!.jsonArray

        for (testCase in testCases) {
            logger.d(testCase.jsonObject["comment"]!!.jsonPrimitive.content)

            val rand_ = ByteVector32(
                testCase.getValue("rand")
            )
            val secretShare = testCase.getValueOrNull("secshare")?.let { ByteVector32(it) }
            val publicShare = testCase.getValueOrNull("pubshare")?.let { PublicKey(it) }

            val thresholdPublicKey = testCase.getValueOrNull("thresh_pk_xonly")?.let {
                XonlyPublicKey(
                    ByteVector32(it)
                )
            }

            val message = testCase.getValueOrNull("msg")
            val extraIn = testCase.getValueOrNull("extra_in")

            val expected = testCase.jsonObject["expected"]!!.jsonArray
            val expectedSecretNonce = Hex.decode(expected[0].jsonPrimitive.content)
            val expectedPublicNonce = Hex.decode(expected[1].jsonPrimitive.content)

            val actualGeneratedNonce = Frost.nonceGen(
                rand_ = rand_,
                secretShare = secretShare,
                publicShare = publicShare,
                thresholdPublicKey = thresholdPublicKey,
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

        val validTestCases = tests.jsonObject["valid_tests"]!!.jsonArray

        for (validTestCase in validTestCases) {
            val publicNonces =
                validTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                    testFrostPublicNonces[jsonElement.jsonPrimitive.int]
                }

            val expectedAggregateNonce =
                Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

            assertContentEquals(
                expectedAggregateNonce,
                Frost.nonceAgg(publicNonces),
                "Aggregate nonce doesn't match"
            )
        }


        val errorTestCases = tests.jsonObject["error_tests"]!!.jsonArray
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

        for (group in testData.jsonObject["test_groups"]!!.jsonArray) {
            val n = group.jsonObject["n"]!!.jsonPrimitive.int
            val t = group.jsonObject["t"]!!.jsonPrimitive.int

            val publicShares = group.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
                PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            val thresholdPublicKey = PublicKey(
                group.getValue("thresh_pk")
            )

            val secretShares = group.jsonObject["secshares"]!!.jsonArray.map { jsonElement ->
                ByteVector32(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            for (i in 0 until n) {
                assertEquals(
                    publicShares[i],
                    Frost.individualPublicKey(secretShares[i])
                )
            }

            val secretNoncesBytes = group.jsonObject["secnonces"]!!.jsonArray.map { jsonElement ->
                Hex.decode(jsonElement.jsonPrimitive.content)
            }
            val frostPublicNonces = group.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
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

            for (validTestCase in group.jsonObject["valid_tests"]!!.jsonArray) {
                logger.d(validTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

                val identifiersTemp = validTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int
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

                val message = Hex.decode(validTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
                val myIdentifier = validTestCase.jsonObject["my_id"]!!.jsonPrimitive.int
                val signerIndex = identifiersTemp.indexOf(myIdentifier)
                val secretShare = secretShares[validTestCase.jsonObject["secshare_index"]!!.jsonPrimitive.int]
                val expectedPartialSignature = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

                val frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    thresholdPublicKey = thresholdPublicKey
                )
                val frostSessionContext = FrostSessionContext(
                    frostSignersContext = frostSignersContext,
                    aggNonce = aggregateNonceTemp,
                    tweaks = listOf(),
                    isXonlies = listOf(),
                    message = message
                )
                val frostSecretNonceTemp = FrostSecretNonce(
                    secretNoncesBytes[validTestCase.jsonObject["secnonce_index"]!!.jsonPrimitive.int]
                )

                val partialSignature = frostSessionContext.sign(
                    frostSecretNonceTemp, secretShare, myIdentifier
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

            for (signErrorTestCase in group.jsonObject["sign_error_tests"]!!.jsonArray) {
                logger.d(signErrorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

                val (expectedException, exceptionProcessor) = signErrorTestCase.getErrorDetails("error")

                val identifiersTemp = signErrorTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int
                }
                val pubicSharesTemp =
                    signErrorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                        publicShares[jsonElement.jsonPrimitive.int]
                    }

                val aggregateNonceTemp = Hex.decode(signErrorTestCase.jsonObject["aggnonce"]!!.jsonPrimitive.content)

                val message = Hex.decode(signErrorTestCase.jsonObject["msg"]!!.jsonPrimitive.content)

                val myIdentifier = signErrorTestCase.jsonObject["my_id"]!!.jsonPrimitive.int
                val secretShare = secretShares[signErrorTestCase.jsonObject["secshare_index"]!!.jsonPrimitive.int]

                val frostSecretNonceTemp = FrostSecretNonce(
                    secretNoncesBytes[signErrorTestCase.jsonObject["secnonce_index"]!!.jsonPrimitive.int]
                )
                val frostSessionContext = FrostSessionContext(
                    frostSignersContext = FrostSignersContext(
                        n = n,
                        t = t,
                        identifiers = identifiersTemp,
                        publicShares = pubicSharesTemp,
                        thresholdPublicKey = thresholdPublicKey
                    ),
                    aggregateNonceTemp,
                    listOf(),
                    listOf(),
                    message
                )


                val throwable = assertFailsWith<Throwable> {
                    frostSessionContext.sign(
                        frostSecretNonceTemp,
                        secretShare,
                        myIdentifier,
                    )
                }

                throwable.testThrowable(
                    expectedException,
                    exceptionProcessor
                )
            }

            for (verifyFailTestCase in group.jsonObject["verify_fail_tests"]!!.jsonArray) {
                logger.d(verifyFailTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")
                val partialSignature = Hex.decode(verifyFailTestCase.jsonObject["psig"]!!.jsonPrimitive.content)

                val identifiersTemp = verifyFailTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int
                }

                val pubicSharesTemp =
                    verifyFailTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                        publicShares[jsonElement.jsonPrimitive.int]
                    }
                val publicNoncesTemp =
                    verifyFailTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                        frostPublicNonces[jsonElement.jsonPrimitive.int]
                    }

                val message = Hex.decode(verifyFailTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
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
                            thresholdPublicKey = thresholdPublicKey
                        ),
                        tweaks = listOf(),
                        isXonlies = listOf(),
                        message = message,
                        index = signerIndex
                    )
                )
            }

            for (verifyErrorTestCase in group.jsonObject["verify_error_tests"]!!.jsonArray) {
                logger.d(verifyErrorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

                val (expectedException, exceptionProcessor) = verifyErrorTestCase.getErrorDetails("error")

                val partialSignature = Hex.decode(verifyErrorTestCase.jsonObject["psig"]!!.jsonPrimitive.content)

                val identifiersTemp = verifyErrorTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.int
                }

                val pubicSharesTemp =
                    verifyErrorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                        publicShares[jsonElement.jsonPrimitive.int]
                    }
                val publicNoncesTemp =
                    verifyErrorTestCase.jsonObject["pubnonce_indices"]!!.jsonArray.map { jsonElement ->
                        frostPublicNonces[jsonElement.jsonPrimitive.int]
                    }

                val message = Hex.decode(verifyErrorTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
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
                            thresholdPublicKey = thresholdPublicKey
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
    }

    @Test
    fun `test tweak vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/tweak_vectors.json")

        for (group in testData.jsonObject["test_groups"]!!.jsonArray) {
            val n = group.jsonObject["n"]!!.jsonPrimitive.int
            val t = group.jsonObject["t"]!!.jsonPrimitive.int

            val publicShares = group.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
                PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            val thresholdPublicKey = PublicKey(
                group.getValue("thresh_pk")
            )

            val secretShares = group.jsonObject["secshares"]!!.jsonArray.map { jsonElement ->
                ByteVector32(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            for (i in 0 until n) {
                assertEquals(
                    publicShares[i],
                    Frost.individualPublicKey(secretShares[i])
                )
            }

            val secretNoncesBytes = group.jsonObject["secnonces"]!!.jsonArray.map { jsonElement ->
                Hex.decode(jsonElement.jsonPrimitive.content)
            }
            val frostPublicNonces = group.jsonObject["pubnonces"]!!.jsonArray.map { jsonElement ->
                FrostPublicNonce(
                    Hex.decode(jsonElement.jsonPrimitive.content)
                )
            }

            val tweaks = group.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
                Hex.decode(jsonElement.jsonPrimitive.content)
            }

            for (validTestCase in group.jsonObject["valid_tests"]!!.jsonArray) {
                logger.d(validTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")
                val identifiersTemp =
                    validTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.int
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

                val message = Hex.decode(validTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
                val myIdentifier = validTestCase.jsonObject["my_id"]!!.jsonPrimitive.int
                val signerIndex = identifiersTemp.indexOf(myIdentifier)
                val secretShare = secretShares[validTestCase.jsonObject["secshare_index"]!!.jsonPrimitive.int]

                val expected = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

                val frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    thresholdPublicKey = thresholdPublicKey
                )
                val frostSessionContext = FrostSessionContext(
                    frostSignersContext = frostSignersContext,
                    aggregateNonceTemp,
                    tweaksTemp,
                    tweakModesTemp,
                    message
                )

                val frostSecretNonceTemp = FrostSecretNonce(
                    secretNoncesBytes[validTestCase.jsonObject["secnonce_index"]!!.jsonPrimitive.int]
                )

                val partialSignature = frostSessionContext.sign(
                    frostSecretNonceTemp, secretShare, myIdentifier
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
                        frostSignersContext = frostSignersContext,
                        tweaks = tweaksTemp,
                        isXonlies = tweakModesTemp,
                        message = message,
                        index = signerIndex
                    ),
                    "partialSignatureVerify failed"
                )
            }

            for (errorTestCase in group.jsonObject["error_tests"]!!.jsonArray) {
                logger.d(errorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

                val (expectedException, exceptionProcessor) = errorTestCase.getErrorDetails("error")

                val identifiersTemp =
                    errorTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.int
                    }
                val pubicSharesTemp =
                    errorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                        publicShares[jsonElement.jsonPrimitive.int]
                    }

                val aggregateNonceTemp = Hex.decode(errorTestCase.jsonObject["aggnonce"]!!.jsonPrimitive.content)

                val tweaksTemp = errorTestCase.jsonObject["tweak_indices"]!!.jsonArray.map { jsonElement ->
                    tweaks[jsonElement.jsonPrimitive.int]
                }
                val tweakModesTemp = errorTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.boolean
                }

                val message = Hex.decode(errorTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
                val myIdentifier = errorTestCase.jsonObject["my_id"]!!.jsonPrimitive.int
                val secretShare = secretShares[errorTestCase.jsonObject["secshare_index"]!!.jsonPrimitive.int]

                val frostSessionContext = FrostSessionContext(frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    thresholdPublicKey = thresholdPublicKey
                ),
                    aggregateNonceTemp,
                    tweaksTemp,
                    tweakModesTemp,
                    message
                )

                val throwable = assertFailsWith<Throwable> {
                    frostSessionContext.sign(
                        FrostSecretNonce(secretNoncesBytes[errorTestCase.jsonObject["secnonce_index"]!!.jsonPrimitive.int]),
                        secretShare,
                        myIdentifier,
                    )
                }

                throwable.testThrowable(
                    expectedException,
                    exceptionProcessor
                )
            }
        }
    }

    @Test
    fun `test det sign vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/det_sign_vectors.json")

        for (group in testData.jsonObject["test_groups"]!!.jsonArray) {
            val n = group.jsonObject["n"]!!.jsonPrimitive.int
            val t = group.jsonObject["t"]!!.jsonPrimitive.int

            val publicShares = group.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
                PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            val thresholdPublicKey = PublicKey(
                group.getValue("thresh_pk")
            )

            val secretShares = group.jsonObject["secshares"]!!.jsonArray.map { jsonElement ->
                ByteVector32(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            for (i in 0 until n) {
                assertEquals(
                    publicShares[i],
                    Frost.individualPublicKey(secretShares[i])
                )
            }

            for (validTestCase in group.jsonObject["valid_tests"]!!.jsonArray) {
                logger.d(validTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

                val identifiersTemp =
                    validTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.int
                    }

                val pubicSharesTemp =
                    validTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                        publicShares[jsonElement.jsonPrimitive.int]
                    }

                val aggothernonce = validTestCase.jsonObject["aggothernonce"]!!.jsonPrimitive.contentOrNull?.let {
                    FrostPublicNonce(Hex.decode(it))
                }

                val tweaks = validTestCase.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
                    Hex.decode(jsonElement.jsonPrimitive.content)
                }

                val tweakModesTemp =
                    validTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.boolean
                    }

                val message = Hex.decode(validTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
                val myIdentifier = validTestCase.jsonObject["my_id"]!!.jsonPrimitive.int
                val signerIndex = identifiersTemp.indexOf(myIdentifier)
                val secretShare = secretShares[validTestCase.jsonObject["secshare_index"]!!.jsonPrimitive.int]

                val rand = validTestCase.jsonObject["aux_rand"]!!.jsonPrimitive.contentOrNull?.let { Hex.decode(it) }

                val expected = validTestCase.jsonObject["expected"]!!.jsonArray.map { jsonElement ->
                    Hex.decode(jsonElement.jsonPrimitive.content)
                }

                val frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    thresholdPublicKey = thresholdPublicKey
                )

                val (publicNonce, partialSignature) = Frost.deterministicSign(
                    secretShare,
                    myIdentifier,
                    aggothernonce,
                    frostSignersContext,
                    tweaks,
                    isXonlies = tweakModesTemp,
                    message,
                    rand
                )

                assertContentEquals(
                    expected[0],
                    publicNonce.value
                )

                assertContentEquals(
                    expected[1],
                    partialSignature.value.toByteArray()
                )

                // For a sole signer, aggothernonce is null and the aggnonce equals
                // the signer's own pubnonce; skip the multi-party aggregation path.
                val aggNonceTemp = if (aggothernonce != null) {
                    Frost.nonceAgg(
                        listOf(publicNonce, aggothernonce)
                    )
                } else {
                    publicNonce.value
                }
                val sessionContext = FrostSessionContext(
                    frostSignersContext = frostSignersContext,
                    aggNonce = aggNonceTemp,
                    tweaks = tweaks,
                    isXonlies = tweakModesTemp,
                    message = message
                )

                assertTrue {
                    sessionContext.partialSignatureVerify(
                        frostPartialSignature = partialSignature,
                        my_id = myIdentifier,
                        frostPublicNonce = publicNonce,
                        publicShare = pubicSharesTemp[signerIndex],
                    )
                }
            }

            for (errorTestCase in group.jsonObject["error_tests"]!!.jsonArray) {
                logger.d(errorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

                val (expectedException, exceptionProcessor) = errorTestCase.getErrorDetails("error")

                val identifiersTemp =
                    errorTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.int
                    }

                val pubicSharesTemp =
                    errorTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                        publicShares[jsonElement.jsonPrimitive.int]
                    }

                val aggothernonce = errorTestCase.jsonObject["aggothernonce"]!!.jsonPrimitive.contentOrNull?.let {
                    FrostPublicNonce(Hex.decode(it))
                }

                val tweaks = errorTestCase.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
                    Hex.decode(jsonElement.jsonPrimitive.content)
                }

                val tweakModesTemp =
                    errorTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.boolean
                    }

                val message = Hex.decode(errorTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
                val myIdentifier = errorTestCase.jsonObject["my_id"]!!.jsonPrimitive.int
                val secretShare = secretShares[errorTestCase.jsonObject["secshare_index"]!!.jsonPrimitive.int]

                val rand = errorTestCase.jsonObject["aux_rand"]!!.jsonPrimitive.contentOrNull?.let { Hex.decode(it) }

                val frostSignersContext = FrostSignersContext(
                    n = n,
                    t = t,
                    identifiers = identifiersTemp,
                    publicShares = pubicSharesTemp,
                    thresholdPublicKey = thresholdPublicKey
                )

                val throwable = assertFailsWith<Throwable> {
                    Frost.deterministicSign(
                        secretShare,
                        myIdentifier,
                        aggothernonce,
                        frostSignersContext,
                        tweaks,
                        isXonlies = tweakModesTemp,
                        message,
                        rand
                    )
                }

                throwable.testThrowable(
                    expectedException,
                    exceptionProcessor
                )
            }
        }
    }

    @Test
    fun `test sig agg vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/sig_agg_vectors.json")

        for (group in testData.jsonObject["test_groups"]!!.jsonArray) {
            val n = group.jsonObject["n"]!!.jsonPrimitive.int
            val t = group.jsonObject["t"]!!.jsonPrimitive.int

            val publicShares = group.jsonObject["pubshares"]!!.jsonArray.map { jsonElement ->
                PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            val thresholdPublicKey = PublicKey(
                group.getValue("thresh_pk")
            )

            val tweaks = group.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
                Hex.decode(jsonElement.jsonPrimitive.content)
            }

            for (validTestCase in group.jsonObject["valid_tests"]!!.jsonArray) {
                val identifiersTemp =
                    validTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.int
                    }
                val pubicSharesTemp =
                    validTestCase.jsonObject["pubshare_indices"]!!.jsonArray.map { jsonElement ->
                        publicShares[jsonElement.jsonPrimitive.int]
                    }

                val aggregateNonceTemp = Hex.decode(validTestCase.jsonObject["aggnonce"]!!.jsonPrimitive.content)

                val tweaksTemp = validTestCase.jsonObject["tweak_indices"]!!.jsonArray.map { jsonElement ->
                    tweaks[jsonElement.jsonPrimitive.int]
                }
                val tweakModesTemp = validTestCase.jsonObject["is_xonly"]!!.jsonArray.map { jsonElement ->
                    jsonElement.jsonPrimitive.boolean
                }

                val partialSignaturesTemp = validTestCase.jsonObject["psigs"]!!.jsonArray.map { jsonElement ->
                    FrostPartialSignature(
                        ByteVector32(
                            Hex.decode(jsonElement.jsonPrimitive.content)
                        )
                    )
                }

                val message = Hex.decode(validTestCase.jsonObject["msg"]!!.jsonPrimitive.content)
                val expected = Hex.decode(validTestCase.jsonObject["expected"]!!.jsonPrimitive.content)

                val frostSessionContext = FrostSessionContext(
                    frostSignersContext = FrostSignersContext(
                        n = n,
                        t = t,
                        identifiers = identifiersTemp,
                        publicShares = pubicSharesTemp,
                        thresholdPublicKey = thresholdPublicKey
                    ),
                    aggregateNonceTemp,
                    tweaksTemp,
                    tweakModesTemp,
                    message
                )

                val signature = frostSessionContext.partialSignatureAggregate(
                    partialSignaturesTemp
                )

                assertContentEquals(
                    expected,
                    signature
                )
                val tweakContext = Frost.thresholdPublicKeyAndTweak(
                    thresholdPublicKey,
                    tweaksTemp,
                    tweakModesTemp
                )
                val tweakedThresholdPublicKey = tweakContext.getXonlyPublicKey()

                assertTrue(
                    Secp256k1.verifySchnorr(
                        pub = tweakedThresholdPublicKey.value.toByteArray(),
                        data = message,
                        signature = signature,
                    ),
                    "Schnorr signature verification failure"
                )
            }

            for (errorTestCase in group.jsonObject["error_tests"]!!.jsonArray) {
                logger.d(errorTestCase.jsonObject["comment"]?.jsonPrimitive?.content ?: "")

                val (expectedException, exceptionProcessor) = errorTestCase.getErrorDetails("error")

                val identifiersTemp =
                    errorTestCase.jsonObject["ids"]!!.jsonArray.map { jsonElement ->
                        jsonElement.jsonPrimitive.int
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
                    FrostPartialSignature(
                        ByteVector32(
                            Hex.decode(jsonElement.jsonPrimitive.content)
                        )
                    )
                }

                val message = Hex.decode(errorTestCase.jsonObject["msg"]!!.jsonPrimitive.content)

                val frostSessionContext = FrostSessionContext(
                    frostSignersContext = FrostSignersContext(
                        n = n,
                        t = t,
                        identifiers = identifiersTemp,
                        publicShares = pubicSharesTemp,
                        thresholdPublicKey = thresholdPublicKey
                    ),
                    aggregateNonceTemp,
                    tweaksTemp,
                    tweakModesTemp,
                    message
                )

                val throwable = assertFailsWith<Throwable> {
                    frostSessionContext.partialSignatureAggregate(
                        partialSignaturesTemp,
                    )
                }

                throwable.testThrowable(
                    expectedException,
                    exceptionProcessor
                )
            }
        }
    }
}
