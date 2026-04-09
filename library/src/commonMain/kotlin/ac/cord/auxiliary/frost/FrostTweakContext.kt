package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.CryptographicConstants
import ac.cord.auxiliary.cryptography.CryptographicConstants.n
import ac.cord.auxiliary.cryptography.Point
import ac.cord.auxiliary.cryptography.toBigInteger
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey

data class FrostTweakContext(
    val Q: Point,
    val gacc: BigInteger,
    val tacc: BigInteger
) {
    val logger = Logger.withTag("FrostTweakContext")

    constructor(groupPublicKey: PublicKey): this(
        Q = Point.fromCompressedBytes(groupPublicKey.value.toByteArray()),
        gacc = BigInteger.ONE,
        tacc = BigInteger.ZERO
    )

    fun getXonlyPublicKey(): XonlyPublicKey {
        return XonlyPublicKey(
            ByteVector32(Q.xbytes())
        )
    }

    fun getPlainPublicKey(): PublicKey {
        return PublicKey(
            Q.cbytes()
        )
    }

    private fun computeG(isXonly: Boolean): BigInteger {
        return  if (isXonly && !Q.hasEvenY()) {
            CryptographicConstants.n - 1
        } else {
            BigInteger.ONE
        }
    }
    fun applyTweak(tweak: ByteVector32, isXonly: Boolean): FrostTweakContext {

        val g = computeG(isXonly)

        val t = tweak.toByteArray().toBigInteger()

        if (t >= CryptographicConstants.n) {
            throw IllegalArgumentException("The tweak must be less than n.")
        }

        val Q_ = Q.mul(g)?.add(
            Point.G.mul(t)
        )
        if (Q_ == null) {
            throw IllegalStateException("The result of tweaking cannot be infinity.")
        }

        val gacc_ = g.times(gacc).mod(n)

        val tacc_ = t.plus(g.times(tacc)).mod(n)

        return FrostTweakContext(
            Q_,
            gacc_,
            tacc_
        )
    }


}
