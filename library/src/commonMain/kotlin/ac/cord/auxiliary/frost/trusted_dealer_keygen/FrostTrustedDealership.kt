package ac.cord.auxiliary.frost.trusted_dealer_keygen

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey

data class FrostTrustedDealership(
    val thresholdPublicKey: PublicKey,
    val secretShares: List<ByteVector32>,
    val publicShares: List<PublicKey>,
    val identifiers: List<Int>
)
