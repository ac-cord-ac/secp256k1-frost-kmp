package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealer
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealership
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.lightning.utils.secure
import fr.acinq.secp256k1.Secp256k1
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
            thresholdSecretBytes = Random.secure().nextBytes(32),
            n = n,
            t = t
        )
        logger.d("${frostTrustedDealership.thresholdPublicKey} ${frostTrustedDealership.secretShares.map { it.toHexString() }} ${frostTrustedDealership.publicShares} ${frostTrustedDealership.identifiers}")

        require(frostTrustedDealership.secretShares.size == n) { "The number of secret shares needs to match n" }


        return frostTrustedDealership
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun `test sign and verify random`() {
        val iteration = 2

        val n = Random.secure().nextInt(2, 11)
        logger.d("n: $n")
        val t = Random.secure().nextInt(2, n+1)
        logger.d("t: $t")

        val frostTrustedDealership = generateFrostKeys(n, t)

        require(frostTrustedDealership.identifiers.size == frostTrustedDealership.secretShares.size)
        require(frostTrustedDealership.secretShares.size == n)

        val signerCount = Random.secure().nextInt(t, n+1)
        val signerIndices = IntRange(0, signerCount-1).shuffled()

        logger.d("Signer Count: $signerCount")
        logger.d("Signer Indices: $signerIndices")
        require(
            signerIndices.toSet().size == signerCount
        )

        val signerIdentifiers = signerIndices.map { frostTrustedDealership.identifiers[it] }
        val signerPublicShares = signerIdentifiers.map { frostTrustedDealership.publicShares[it] }
        val signerSecretShares = signerIdentifiers.map { frostTrustedDealership.secretShares[it] }

        val frostSignerContext = FrostSignersContext(
            n = n,
            t = t,
            identifiers = signerIdentifiers,
            publicShares = signerPublicShares,
            groupPublicKey = frostTrustedDealership.thresholdPublicKey
        )

        val message = Random.secure().nextBytes(32)
        val v = Random.secure().nextInt(0, 4)
        print("v: $v")
        val tweaks = IntRange(0, v-1).map {
            ByteVector32(
                Random.secure().nextBytes(32)
            )
        }
        val tweaksModes = IntRange(0, v-1).map { Random.secure().nextBoolean() }

        val tweakedThresholdPublicKey = Frost.groupPublicKeyAndTweet(
            frostTrustedDealership.thresholdPublicKey,
            tweaks,
            isXonlies = tweaksModes
        ).getXonlyPublicKey()

        val signerSecretNonces = mutableListOf<FrostSecretNonce>()
        val signerPublicNonces = mutableListOf<FrostPublicNonce>()

        IntRange(0, signerCount-1).forEach {  index ->
            val timestamp = Clock.System.now()

            val (frostSecretNonce, publicNonce) = Frost.nonceGen(
                secretShare = signerSecretShares[index],
                publicShare = signerPublicShares[index],
                groupPublicKey = tweakedThresholdPublicKey,
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
            logger.d("Index: $index")
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

        assertTrue {
            Secp256k1.verifySchnorr(
                signature = bip340Signature,
                data = message,
                pub = tweakedThresholdPublicKey.value.toByteArray()
            )
        }
    }
}