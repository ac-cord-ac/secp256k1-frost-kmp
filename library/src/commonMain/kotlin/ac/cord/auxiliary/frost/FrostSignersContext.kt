package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.PublicKey

data class FrostSignersContext(
    val n: Int,
    val t: Int,
    val identifiers: List<Int>,
    val publicShares: List<PublicKey>,
    val thresholdPublicKey: PublicKey
) {
    val logger = Logger.withTag("FrostSignersContext")
    fun validateSignersContext() {
        if (t < 1 || t > n) {
            throw IllegalArgumentException("The threshold must be 1 <= t <= n.")
        }
        if (identifiers.size !in t..n) {
            throw IllegalArgumentException("The number of signers must be between t and n.")
        }

        if (publicShares.size != identifiers.size) {
            throw IllegalArgumentException("The pubshares and ids arrays must have the same length.")
        }
        identifiers.zip(publicShares).forEachIndexed { index, (identifier, publicShare) ->
            if (identifier.toBigInteger().intValue() !in 0..<n) {
                throw IllegalArgumentException("The participant identifier at index $index is out of range.")
            }

            try {
                GroupElement.fromCompressedBytes(publicShare)
            } catch (e: Exception) {
                // A malformed pubshare is invalid pre-protocol input, not a protocol
                // contribution: the signers context is agreed upon before signing
                // begins, so we signal it with IllegalArgumentException rather than
                // blaming a signer via InvalidContributionException.
                throw IllegalArgumentException("Invalid pubshare at index $index.", e)
            }
        }

        if (identifiers.toSet().size != identifiers.size) {
            throw IllegalArgumentException("The participant identifier list contains duplicate elements.")
        }

        if (deriveThresholdPublicKey() != thresholdPublicKey) {
            throw IllegalArgumentException("The provided key material is incorrect.")
        }
    }

    fun deriveThresholdPublicKey(): PublicKey {
        var Q = GroupElement.INFINITY

        identifiers.zip(publicShares).forEachIndexed { index, (identifier, publicShare) ->
            val X_i = try {
                GroupElement.fromCompressedBytes(publicShare)
            } catch (e: Exception) {
                throw InvalidContributionException(index.toBigInteger(), "pubshare", e)
            }
            val lam_i = Frost.deriveInterpolatingValue(
                identifiers,
                identifier
            )
            val multiple = X_i.mul(lam_i.toBigInteger())
            Q = Q.add(multiple)
        }

        require(!Q.isInfinity) {"The threshold pubkey must not be the point at infinity."}
        return Q.toCompressedBytes()
    }


}
