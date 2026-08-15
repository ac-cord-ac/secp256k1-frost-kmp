package ac.cord.auxiliary.frost

import ac.cord.auxiliary.TestHelpers
import ac.cord.auxiliary.extensions.getValue
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealer
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealership
import co.touchlab.kermit.Logger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RandomSignAndVerifyTests {
    val logger = Logger.withTag("RandomSignAndVerifyTests")

    private fun generateFrostKeys(random: Random, n: Int, t: Int): FrostTrustedDealership {
        if (t !in 2..n) {
            throw IllegalArgumentException("values must satisfy: 2 <= t <= n")
        }
        val frostTrustedDealership = FrostTrustedDealer.keyGen(
            thresholdSecretBytes = ByteVector32(
                random.nextBytes(32)
            ),
            n = n,
            t = t
        )

        require(frostTrustedDealership.secretShares.size == n) { "The number of secret shares needs to match n" }


        return frostTrustedDealership
    }

    private fun testSignAndVerify(
        random: Random,
        iteration: Int,
        n: Int,
        t: Int,
        frostTrustedDealership: FrostTrustedDealership,
        signerCount: Int,
        signerIndices: List<Int>,
        message: ByteArray,
        tweaks: List<ByteArray>,
        tweaksModes: List<Boolean>
    ) {
        logger.d("iteration=$iteration n=$n t=$t signerCount=$signerCount message=${message.toHexString()} thresholdPublicKey=${frostTrustedDealership.thresholdPublicKey} signerIndices=$signerIndices tweaks=$tweaks tweakModes=$tweaksModes")
        require(frostTrustedDealership.identifiers.size == frostTrustedDealership.secretShares.size)
        require(frostTrustedDealership.secretShares.size == n)

        val signerIdentifiers = signerIndices.map { frostTrustedDealership.identifiers[it] }
        val signerPublicShares = signerIdentifiers.map { frostTrustedDealership.publicShares[it] }
        val signerSecretShares = signerIdentifiers.map { frostTrustedDealership.secretShares[it] }

        val frostSignerContext = FrostSignersContext(
            n = n,
            t = t,
            identifiers = signerIdentifiers,
            publicShares = signerPublicShares,
            thresholdPublicKey = frostTrustedDealership.thresholdPublicKey
        )

        val tweakedThresholdPublicKey = Frost.thresholdPublicKeyAndTweak(
            frostTrustedDealership.thresholdPublicKey,
            tweaks,
            isXonlies = tweaksModes
        ).getXonlyPublicKey()

        val signerSecretNonces = mutableListOf<FrostSecretNonce>()
        val signerPublicNonces = mutableListOf<FrostPublicNonce>()

        (0 until signerCount-1).forEach {  index ->
            val (frostSecretNonce, publicNonce) = Frost.nonceGen(
                rand_ = ByteVector32(random.nextBytes(32)),
                secretShare = signerSecretShares[index],
                publicShare = signerPublicShares[index],
                thresholdPublicKey = tweakedThresholdPublicKey,
                message = message,
                extraIn = random.nextBytes(8)
            )

            signerSecretNonces.add(
                frostSecretNonce
            )
            signerPublicNonces.add(
                publicNonce
            )
        }

        // On even iterations use regular signing algorithm for the final signer,
        // otherwise use deterministic signing algorithm
        val (publicNonceFinal, partialSignatureFinal) = if (iteration.mod(2) == 0) {
            val (secretNonceFinal, publicNonceFinal) = Frost.nonceGen(
                rand_ = ByteVector32(random.nextBytes(32)),
                secretShare = signerSecretShares.last(),
                publicShare = signerPublicShares.last(),
                thresholdPublicKey = tweakedThresholdPublicKey,
                message = message,
                extraIn = random.nextBytes(8)
            )
            signerSecretNonces.add(
                secretNonceFinal
            )

            Pair(
                publicNonceFinal,
                null
            )
        } else {
            // A sole signer has no other nonces to aggregate, so aggothernonce is omitted.
            val aggOtherNonce = if (signerPublicNonces.isEmpty()) {
                null
            } else {
                FrostPublicNonce(Frost.nonceAgg(signerPublicNonces))
            }
            val rand = random.nextBytes(32)

            val (publicNonceFinal, partialSignatureFinal) = Frost.deterministicSign(
                signerSecretShares.last(),
                signerIdentifiers.last(),
                aggOtherNonce,
                frostSignerContext,
                tweaks,
                isXonlies = tweaksModes,
                message = message,
                rand = rand
            )

            Pair(
                publicNonceFinal,
                partialSignatureFinal
            )
        }

        signerPublicNonces.add(
            publicNonceFinal
        )

        val aggNonce = Frost.nonceAgg(
            signerPublicNonces
        )

        val frostSessionContext = FrostSessionContext(
            aggNonce = aggNonce,
            frostSignersContext = frostSignerContext,
            tweaks = tweaks,
            isXonlies = tweaksModes,
            message = message
        )

        val signerPartialSignatures = mutableListOf<FrostPartialSignature>()

        IntRange(0, signerCount-1).forEach { index ->
            val signerPartialSignature = if (iteration % 2 != 0 && index == signerCount-1) {
                require(partialSignatureFinal != null) { "partialSignatureFinal shouldn't be null for this iteration" }
                partialSignatureFinal
            } else {
                frostSessionContext.sign(
                    signerSecretNonces[index],
                    signerSecretShares[index],
                    signerIdentifiers[index]
                )
            }

            require(
                Frost.partialSignatureVerify(
                    frostPartialSignature = signerPartialSignature,
                    frostPublicNonces = signerPublicNonces,
                    frostSignersContext = frostSignerContext,
                    tweaks = tweaks,
                    isXonlies = tweaksModes,
                    message = message,
                    index = index
                )
            )

            signerPartialSignatures.add(signerPartialSignature)
        }

        // An exception is thrown if secnonce is accidentally reused
        assertFailsWith<IllegalArgumentException> {
            frostSessionContext.sign(
                frostSecretNonce = signerSecretNonces.first(),
                secretShare = signerSecretShares.first(),
                my_id = signerIdentifiers.first(),
            )
        }

        // Fail partial sig verify  at wrong index
        assertFalse {
            Frost.partialSignatureVerify(
                frostPartialSignature = signerPartialSignatures[0],
                frostPublicNonces = signerPublicNonces,
                frostSignersContext = frostSignerContext,
                tweaks = tweaks,
                isXonlies = tweaksModes,
                message = message,
                index = 1
            )
        }

        // Fail partial sig verify with wrong message...
        assertFalse {
            Frost.partialSignatureVerify(
                frostPartialSignature = signerPartialSignatures[0],
                frostPublicNonces = signerPublicNonces,
                frostSignersContext = frostSignerContext,
                tweaks = tweaks,
                isXonlies = tweaksModes,
                random.nextBytes(32), // Random message...
                0
            )
        }

        val bip340Signature = frostSessionContext.partialSignatureAggregate(
            signerPartialSignatures
        )

        assertTrue(
            Secp256k1.verifySchnorr(
                signature = bip340Signature,
                data = message,
                pub = tweakedThresholdPublicKey.value.toByteArray()
            ),
            "BIP340 Schnorr signature verification failed"
        )
    }

    @Test
    fun `test sign and verify random`() {
        val random = Random(42) // seeded for reproducibility
        for (iteration in (0..6)) {
            val n = random.nextInt(2, 11)
            val t = random.nextInt(2, n+1)

            val frostTrustedDealership = generateFrostKeys(random, n, t)

            require(frostTrustedDealership.identifiers.size == frostTrustedDealership.secretShares.size)
            require(frostTrustedDealership.secretShares.size == n)

            val signerCount = random.nextInt(t, n+1)
            val signerIndices = (0 until n).toList().shuffled(random).take(signerCount)

            require(
                signerIndices.toSet().size == signerCount
            )

            //  In this example, the message and threshold pubkey are known
            // before nonce generation, so they can be passed into the nonce
            // generation function as a defense-in-depth measure to protect
            // against nonce reuse.
            //
            // If these values are not known when nonce_gen is called, empty
            // byte arrays can be passed in for the corresponding arguments
            // instead.
            val message = random.nextBytes(32)
            val v = random.nextInt(4)

            val tweaks = (0 until v).map {
                random.nextBytes(32)
            }
            val tweaksModes = (0 until v).map { random.nextBoolean() }

            testSignAndVerify(
                random = random,
                iteration = iteration,
                n = n,
                t = t,
                frostTrustedDealership = frostTrustedDealership,
                signerCount = signerCount,
                signerIndices = signerIndices,
                message = message,
                tweaks = tweaks,
                tweaksModes = tweaksModes
            )
        }
    }

    @Test
    fun `extra sign and verify vectors`() {
        val testData = TestHelpers.readResourceAsJson("vectors/extra_vectors.json")

        for (validTestCase in testData.jsonObject["valid_test_cases"]!!.jsonArray) {

            val iteration = validTestCase.jsonObject["iteration"]!!.jsonPrimitive.int
            val n = validTestCase.jsonObject["n"]!!.jsonPrimitive.int
            val t = validTestCase.jsonObject["t"]!!.jsonPrimitive.int
            val signerCount = validTestCase.jsonObject["signer_count"]!!.jsonPrimitive.int

            val signerIndices = validTestCase.jsonObject["signer_indices"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.int
            }

            val publicShares = validTestCase.jsonObject["public_shares"]!!.jsonArray.map { jsonElement ->
                PublicKey(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            val secretShares = validTestCase.jsonObject["secret_shares"]!!.jsonArray.map { jsonElement ->
                ByteVector32(Hex.decode(jsonElement.jsonPrimitive.content))
            }

            val thresholdPublicKey = PublicKey(
                validTestCase.getValue("threshold_pk")
            )

            val tweaks = validTestCase.jsonObject["tweaks"]!!.jsonArray.map { jsonElement ->
                Hex.decode(jsonElement.jsonPrimitive.content)
            }
            val tweakModesTemp = validTestCase.jsonObject["tweak_modes"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.boolean
            }

            val message = Hex.decode(validTestCase.jsonObject["message"]!!.jsonPrimitive.content)

            // The trusted dealer is deterministic: re-deriving the keys from the
            // threshold secret must reproduce the shares in this vector.
            val thresholdSecret = ByteVector32(validTestCase.getValue("thresh_sk"))
            val regeneratedDealership = FrostTrustedDealer.keyGen(thresholdSecret, n, t)
            assertEquals(thresholdPublicKey, regeneratedDealership.thresholdPublicKey)
            assertEquals(secretShares, regeneratedDealership.secretShares)
            assertEquals(publicShares, regeneratedDealership.publicShares)

            testSignAndVerify(
                random = Random(42), // seeded for reproducibility
                iteration = iteration,
                n = n,
                t = t,
                frostTrustedDealership = FrostTrustedDealership(
                    thresholdPublicKey = thresholdPublicKey,
                    secretShares = secretShares,
                    publicShares = publicShares,
                    identifiers = publicShares.indices.toList()
                ),
                tweaks = tweaks,
                tweaksModes = tweakModesTemp,
                message = message,
                signerCount = signerCount,
                signerIndices = signerIndices
            )
        }
    }
}
