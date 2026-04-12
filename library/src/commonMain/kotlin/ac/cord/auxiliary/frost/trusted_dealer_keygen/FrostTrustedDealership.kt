package ac.cord.auxiliary.frost.trusted_dealer_keygen

import fr.acinq.bitcoin.PublicKey

data class FrostTrustedDealership(
    val thresholdPublicKey: PublicKey,
    val secretShares: List<ByteArray>,
    val publicShares: List<PublicKey>,
    val identifiers: List<Int>
)
