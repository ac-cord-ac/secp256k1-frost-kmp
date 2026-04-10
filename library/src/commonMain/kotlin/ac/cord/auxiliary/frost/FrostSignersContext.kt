package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Point
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey

data class FrostSignersContext(
    val n: Int,
    val t: Int,
    val identifiers: List<Int>,
    val publicShares: List<PublicKey>,
    val groupPublicKey: PublicKey
) {
    val logger = Logger.withTag("FrostSignersContext")
    fun validateSignersContext() {
        require(t <= n) {"Threshold has to be below or equal to number of signers"}
        if (identifiers.size !in t..n) {
            throw IllegalArgumentException("The number of signers must be between t and n.")
        }

        if (publicShares.size != identifiers.size) {
            throw IllegalArgumentException("The pubshares and ids arrays must have the same length.")
        }
        identifiers.zip(publicShares).forEachIndexed { index, (identifier, publicShare) ->
            if (identifier.toBigInteger().intValue() !in 0..<n) {
                throw IllegalArgumentException("The participant identifier $index is out of range.")
            }

            try {
                GroupElement.fromCompressedBytes(publicShare)
            } catch (e: Throwable) {
                throw InvalidContributionException(index.toBigInteger(), "pubshare", e)
            }
        }

        if (identifiers.toSet().size != identifiers.size) {
            throw IllegalArgumentException("The participant identifier list contains duplicate elements.")
        }
        if (deriveThresholdPublicKey() != groupPublicKey) {
            throw IllegalArgumentException("The provided key material ($groupPublicKey) is incorrect ${deriveThresholdPublicKey()}.")
        }
    }

    fun deriveThresholdPublicKey(): PublicKey {
        var Q = GroupElement.INFINITY

        identifiers.zip(publicShares).forEachIndexed { index, (identifier, publicShare) ->
            val X_i = try {
                GroupElement.fromCompressedBytes(publicShare)
            } catch (e: Throwable) {
                throw InvalidContributionException(index.toBigInteger(), "pubshare", e)
            }
            logger.d("X_i: $X_i")
            val lam_i = Frost.deriveInterpolatingValue(
                identifiers,
                identifier
            )
            logger.d("lamI: $lam_i")
            Q = X_i.mul(lam_i)?.add(Q) ?: Q
            logger.d("Q: $Q")
        }

        require(!Q.isInfinity) {"Q should not be at infinity"}
        return Q.toCompressedBytes()
    }


}
