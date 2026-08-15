package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey

data class FrostTweakContext(
    val Q: GroupElement,
    val gacc: Scalar,
    val tacc: Scalar
) {
    val logger = Logger.withTag("FrostTweakContext")

    constructor(thresholdPublicKey: PublicKey): this(
        Q = GroupElement.fromCompressedBytes(thresholdPublicKey),
        gacc = Scalar(BigInteger.ONE),
        tacc = Scalar(BigInteger.ZERO)
    )

    fun getXonlyPublicKey(): XonlyPublicKey {
        return Q.toXonlyPublicKey()
    }

    fun getPlainPublicKey(): PublicKey {
        return Q.toCompressedBytes()
    }

    private fun computeG(isXonly: Boolean): Scalar {
        return Scalar(
            if (isXonly && !Q.hasEvenY()) {
                BigInteger.ONE.negate()
            } else {
                BigInteger.ONE
            }
        )
    }
    fun applyTweak(tweakBytes: ByteArray, isXonly: Boolean): FrostTweakContext {
        if (tweakBytes.size != 32) {
            throw IllegalArgumentException("The tweak must be a 32-byte array.")
        }

        val g = computeG(isXonly)


        val tweak = try {
            Scalar.fromBytesChecked(
                tweakBytes
            )
        } catch (e: Exception) {
            throw IllegalArgumentException("The tweak value is out of range.", e)
        }

        val Q_ = Q.mul(g.toBigInteger()).add(
            GroupElement.GENERATOR_POINT.mul(tweak.toBigInteger())
        )

        if (Q_.isInfinity) {
            throw IllegalArgumentException("The result of tweaking cannot be infinity.")
        }

        val gacc_ = g.times(gacc)
        val tacc_ = tweak.plus(g.times(tacc))

        return FrostTweakContext(
            Q_,
            gacc_,
            tacc_
        )
    }


}
