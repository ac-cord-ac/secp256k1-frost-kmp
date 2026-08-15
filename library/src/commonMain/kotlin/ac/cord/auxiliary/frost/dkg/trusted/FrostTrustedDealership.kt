package ac.cord.auxiliary.frost.dkg.trusted

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey

data class FrostTrustedDealership(
    val thresholdPublicKey: PublicKey,
    val secretShares: List<ByteVector32>,
    val publicShares: List<PublicKey>,
    val identifiers: List<Int>
) {
    override fun toString(): String {
        return "FrostTrustedDealership(thresholdPublicKey=$thresholdPublicKey, secretShares=REDACTED(${secretShares.size} shares), publicShares=$publicShares, identifiers=$identifiers)"
    }
}
