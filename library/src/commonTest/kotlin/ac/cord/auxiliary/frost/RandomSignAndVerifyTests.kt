package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealer
import ac.cord.auxiliary.frost.trusted_dealer_keygen.FrostTrustedDealership
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import korlibs.crypto.SecureRandom
import kotlin.test.Test
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

class RandomSignAndVerifyTests {
    val logger = Logger.withTag("RandomSignAndVerifyTests")

    init {
        SecureRandom.addSeed(
            SecureRandom.nextBytes(64)
        )
    }
    private fun generateFrostKeys(n: Int, t: Int): FrostTrustedDealership {
        if (t !in 2..n) {
            throw IllegalArgumentException("values must satisfy: 2 <= t <= n")
        }
        val frostTrustedDealership = FrostTrustedDealer.keyGen(
            thresholdSecretBytes = SecureRandom.nextBytes(32),
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

        val n = SecureRandom.nextInt(2, 11)
        logger.d("n: $n")
        val t = SecureRandom.nextInt(2, n+1)
        logger.d("t: $t")

        val frostTrustedDealership = generateFrostKeys(n, t)

        require(frostTrustedDealership.identifiers.size == frostTrustedDealership.secretShares.size)
        require(frostTrustedDealership.secretShares.size == n)

        val signerCount = SecureRandom.nextInt(t, n+1)
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

        val message = SecureRandom.nextBytes(32)
        val v = SecureRandom.nextInt(0, 4)
        print("v: $v")
        val tweaks = IntRange(0, v-1).map {
            ByteVector32(
                SecureRandom.nextBytes(32)
            )
        }
        val tweaksModes = IntRange(0, v-1).map { SecureRandom.nextBoolean() }

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
        val publicNonceFinal = if (iteration.mod(2) == 0) {
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

            publicNonceFinal
        } else {
            val aggOtherNonce = Frost.nonceAgg(
                signerPublicNonces
            )
            val rand = SecureRandom.nextBytes(32)

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

            publicNonceFinal
        }

        signerPublicNonces.add(
            publicNonceFinal
        )


    }
}