package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.CryptographicConstants
import ac.cord.auxiliary.cryptography.CryptographicConstants.n
import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.toBigInteger
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey

data class FrostTweakContext(
    val Q: GroupElement,
    val gacc: Scalar,
    val tacc: Scalar
) {
    val logger = Logger.withTag("FrostTweakContext")

    constructor(groupPublicKey: PublicKey): this(
        Q = GroupElement.fromCompressedBytes(groupPublicKey),
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
    fun applyTweak(tweakBytes: ByteVector32, isXonly: Boolean): FrostTweakContext {

        val g = computeG(isXonly)


        val tweak = try {
            Scalar.fromBytesNonZeroChecked(
                tweakBytes.toByteArray()
            )
        } catch (e: Throwable) {
            throw IllegalArgumentException("The tweak must be less than n.", e)
        }

        val Q_ = Q.mul(g.toBigInteger()).add(
            GroupElement.GENERATOR_POINT.mul(tweak.toBigInteger())
        )

        if (Q_.isInfinity) {
            throw IllegalStateException("The result of tweaking cannot be infinity.")
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
