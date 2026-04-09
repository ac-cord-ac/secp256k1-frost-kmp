package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.toBigInteger
import fr.acinq.bitcoin.ByteVector32

data class FrostPartialSignature(
    val value: ByteVector32
) {
    fun toBigInteger() = value.toBigInteger()

}
