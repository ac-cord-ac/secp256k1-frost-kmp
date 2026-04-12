package ac.cord.auxiliary.frost

import ac.cord.auxiliary.TestHelpers
import ac.cord.auxiliary.extensions.getValue
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealer
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealership
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.lightning.utils.secure
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

class RandomSignAndVerifyTests {
    val logger = Logger.withTag("RandomSignAndVerifyTests")

    private fun generateFrostKeys(n: Int, t: Int): FrostTrustedDealership {
        if (t !in 2..n) {
            throw IllegalArgumentException("values must satisfy: 2 <= t <= n")
        }
        val frostTrustedDealership = FrostTrustedDealer.keyGen(
            thresholdSecretBytes = ByteVector32(
                Random.secure().nextBytes(32)
            ),
            n = n,
            t = t
        )

        require(frostTrustedDealership.secretShares.size == n) { "The number of secret shares needs to match n" }


        return frostTrustedDealership
    }

    @OptIn(ExperimentalTime::class)
    private fun testSignAndVerify(
        iteration: Int,
        n: Int,
        t: Int,
        frostTrustedDealership: FrostTrustedDealership,
        signerCount: Int,
        signerIndices: List<Int>,
        message: ByteArray,
        tweaks: List<ByteVector32>,
        tweaksModes: List<Boolean>
    ) {
        logger.d("iteration=$iteration n=$n t=$t signerCount=$signerCount message=${message.toHexString()} frostTrustedDealership=$frostTrustedDealership signerIndices=$signerIndices  tweaks=$tweaks tweakModes=$tweaksModes")
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
            val timestamp = Clock.System.now()

            val (frostSecretNonce, publicNonce) = Frost.nonceGen(
                secretShare = signerSecretShares[index],
                publicShare = signerPublicShares[index],
                thresholdPublicKey = tweakedThresholdPublicKey,
                message = message,
                timestamp.toEpochMilliseconds().toBigInteger().toByteArray()
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
            val timestamp = Clock.System.now()

            val (secretNonceFinal, publicNonceFinal) = Frost.nonceGen(
                signerSecretShares.last(),
                signerPublicShares.last(),
                tweakedThresholdPublicKey,
                message,
                timestamp.toEpochMilliseconds().toBigInteger().toByteArray()
            )
            signerSecretNonces.add(
                secretNonceFinal
            )

            Pair(
                publicNonceFinal,
                null
            )
        } else {
            val aggOtherNonce = Frost.nonceAgg(
                signerPublicNonces
            )
            val rand = Random.secure().nextBytes(32)

            val (publicNonceFinal, partialSignatureFinal) = Frost.deterministicSign(
                signerSecretShares.last(),
                signerIdentifiers.last(),
                FrostPublicNonce(aggOtherNonce),
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
        val throwable = assertFailsWith<IllegalArgumentException> {
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
                Random.secure().nextBytes(32), // Random message...
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

    @OptIn(ExperimentalTime::class)
    @Test
    fun `test sign and verify random`() {
        for (iteration in (0..6)) {
            val n = Random.secure().nextInt(2, 11)
            val t = Random.secure().nextInt(2, n+1)

            val frostTrustedDealership = generateFrostKeys(n, t)

            require(frostTrustedDealership.identifiers.size == frostTrustedDealership.secretShares.size)
            require(frostTrustedDealership.secretShares.size == n)

            val signerCount = Random.secure().nextInt(t, n+1)
            val signerIndices = IntRange(0, signerCount-1).shuffled()

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
            val message = Random.secure().nextBytes(32)
            val v = Random.secure().nextInt(4)

            val tweaks = (0 until v).map {
                ByteVector32(
                    Random.secure().nextBytes(32)
                )
            }
            val tweaksModes = (0 until v).map { Random.secure().nextBoolean() }

            testSignAndVerify(
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
                ByteVector32(Hex.decode(jsonElement.jsonPrimitive.content))
            }
            val tweakModesTemp = validTestCase.jsonObject["tweak_modes"]!!.jsonArray.map { jsonElement ->
                jsonElement.jsonPrimitive.boolean
            }

            val message = Hex.decode(validTestCase.jsonObject["message"]!!.jsonPrimitive.content)


            testSignAndVerify(
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