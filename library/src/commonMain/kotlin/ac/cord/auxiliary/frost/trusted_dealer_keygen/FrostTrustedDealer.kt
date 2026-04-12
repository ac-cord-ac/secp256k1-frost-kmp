package ac.cord.auxiliary.frost.trusted_dealer_keygen

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.lightning.utils.secure
import kotlin.random.Random

object FrostTrustedDealer {
    val logger = Logger.withTag("FrostTrustedDealer")

    fun keyGen(
        thresholdSecretBytes: ByteArray,
        n: Int,
        t: Int
    ): FrostTrustedDealership {
        require(t in 2..n) { "threshold needs to be between 2 and n" }

        val thresholdSecret = Scalar.fromBytesNonZeroChecked(
            thresholdSecretBytes
        )
        val thresholdPublicKeyGroupElement = GroupElement.GENERATOR_POINT.mul(thresholdSecret.toBigInteger())

        require(!thresholdPublicKeyGroupElement.isInfinity) { "Threshold public key cannot be infininty" }

        val thresholdPublicKey = thresholdPublicKeyGroupElement.toCompressedBytes()

        val coefficients = mutableListOf<Scalar>()
        for (i in 0 until t) {
            coefficients.add(
                Scalar.fromBytesNonZeroChecked(
                    Random.secure().nextBytes(32)
                )
            )
        }

        val secretSharesScalars = secretShareShard(
            thresholdSecret,
            coefficients,
            n
        )

        val secretShares = secretSharesScalars.map { it.toByteArray() }

        val publicShareGroupElements = secretSharesScalars.map { GroupElement.GENERATOR_POINT.mul(it.toBigInteger()) }
        val publicShares = publicShareGroupElements.map { it.toCompressedBytes() }

        return FrostTrustedDealership(
            thresholdPublicKey,
            secretShares,
            publicShares,
            secretShares.indices.toList()
        )
    }

    private fun secretShareShard(secret: Scalar, coefficients: List<Scalar>, n: Int): List<Scalar> {
        val coefficientsWithSecret = coefficients + listOf(secret)

        val secretShares = mutableListOf<Scalar>()

        for (i in 0 until n) {
            val x = Scalar(
                BigInteger.ONE.plus(i)
            )
            val y = polynomialEvaluate(
                coefficientsWithSecret,
                x
            )
            logger.d("y: $y")

            require(y.toBigInteger() != BigInteger.ZERO)

            secretShares.add(y)
        }

        return secretShares
    }

    private fun polynomialEvaluate(coefficientsWithSecret: List<Scalar>, x: Scalar): Scalar {
        return coefficientsWithSecret.reduce { result, coefficient ->
            return result.times(x).plus(coefficient)
        }
    }
}