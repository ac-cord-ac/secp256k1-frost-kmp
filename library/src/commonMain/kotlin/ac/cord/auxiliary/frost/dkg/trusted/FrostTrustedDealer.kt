package ac.cord.auxiliary.frost.dkg.trusted

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import ac.cord.auxiliary.frost.Frost
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.bitcoin.ByteVector32

object FrostTrustedDealer {
    val logger = Logger.withTag("FrostTrustedDealer")

    const val COEFF_DERIVATION_TAG = "BIP0445/trusted/keygen"

    fun keyGen(
        thresholdSecretBytes: ByteVector32,
        n: Int,
        t: Int
    ): FrostTrustedDealership {
        require(t in 1..n) { "values must satisfy: 1 <= t <= n" }

        val thresholdSecret = Scalar.fromBytesNonZeroChecked(
            thresholdSecretBytes.toByteArray()
        )
        val thresholdPublicKeyGroupElement = GroupElement.GENERATOR_POINT.mul(thresholdSecret.toBigInteger())

        require(!thresholdPublicKeyGroupElement.isInfinity) { "Threshold public key cannot be infininty" }

        val thresholdPublicKey = thresholdPublicKeyGroupElement.toCompressedBytes()

        // Derive coefficient i deterministically from the threshold secret and the
        // index, so the same input always yields the same shares.
        val coefficients = (1 until t).map { i ->
            Scalar.fromBytesNonZeroChecked(
                Frost.taggedHash(COEFF_DERIVATION_TAG, thresholdSecretBytes.toByteArray() + i.to4LengthByteArray())
            )
        }

        val secretSharesScalars = secretShareShard(
            thresholdSecret,
            coefficients,
            n
        )

        val secretShares = secretSharesScalars.map {
            ByteVector32(it.toByteArray())
        }

        val publicShareGroupElements = secretSharesScalars.map { GroupElement.GENERATOR_POINT.mul(it.toBigInteger()) }
        val publicShares = publicShareGroupElements.map { it.toCompressedBytes() }

        return FrostTrustedDealership(
            thresholdPublicKey,
            secretShares,
            publicShares,
            secretShares.indices.toList()
        )
    }

    internal fun secretShareShard(secret: Scalar, coefficients: List<Scalar>, n: Int): List<Scalar> {
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

            require(y.toBigInteger() != BigInteger.ZERO)

            secretShares.add(y)
        }

        return secretShares
    }

    internal fun secretShareCombine(
        secretShares: List<Scalar>,
        identifiers: List<Int>
    ): Scalar {
       require(secretShares.size == identifiers.size)
       
       val secret = Scalar(BigInteger.ZERO)
       
       return secretShares.zip(identifiers).map { (secretShare, identifier) ->
           val lam = Frost.deriveInterpolatingValue(
               identifiers,
               identifier
           )

           secretShare.times(lam)
       }.reduce { accumulatedSecret: Scalar, interpolatedSecretShare: Scalar ->
           accumulatedSecret.plus(interpolatedSecretShare)
       }
    }

    internal fun polynomialEvaluate(coefficientsWithSecret: List<Scalar>, x: Scalar): Scalar {
        return coefficientsWithSecret.reduce { result, coefficient ->
            result.times(x).plus(coefficient)
        }
    }
}