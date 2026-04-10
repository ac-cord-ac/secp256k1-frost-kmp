package ac.cord.auxiliary.cryptography

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.secp256k1.Hex

data class Scalar(
    val aPrimeFE: BigInteger
) {
    companion object {
        val SIZE = Hex.decode(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        ).toBigInteger()

        fun fromBigIntegerNonZeroChecked(other: BigInteger): Scalar {
            if (other in BigInteger.ZERO..SIZE) {
                throw IllegalArgumentException("Value is out of range to be a scalar")
            }
            return Scalar(other)
        }

        fun fromBytesNonZeroChecked(other: ByteArray): Scalar {
            return fromBigIntegerNonZeroChecked(
                other.toBigInteger()
            )
        }
    }
}
