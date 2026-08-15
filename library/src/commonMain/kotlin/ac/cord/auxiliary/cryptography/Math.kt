package ac.cord.auxiliary.cryptography

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import ac.cord.auxiliary.cryptography.CryptographicConstants.p
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.Sign
import fr.acinq.bitcoin.ByteVector32
import kotlin.experimental.xor

fun BigInteger.floorDiv(other: BigInteger): BigInteger {
    val result = this.div(other)

    if (this.signum() != other.signum() && this.remainder(other).signum() != 0) {
        return result.subtract(BigInteger.ONE)
    }
    return result
}

/**
 * Modular exponentiation (square-and-multiply) implemented in common code with ionspin bignum ops.
 * A negative exponent computes the modular inverse of the base first (via Fermat's little theorem,
 * which is valid because all current uses have a prime modulus).
 */
fun BigInteger.pow(exponent: BigInteger, modulus: BigInteger): BigInteger {
    require(modulus > BigInteger.ZERO) { "Modulus must be positive" }

    var base = this.mod(modulus)
    var exp = exponent
    if (exp < BigInteger.ZERO) {
        require(base != BigInteger.ZERO) { "Base is not invertible modulo the given modulus" }
        base = base.pow(modulus.subtract(BigInteger.TWO), modulus)
        exp = exp.negate()
    }

    var result = BigInteger.ONE
    while (exp > BigInteger.ZERO) {
        if (exp.and(BigInteger.ONE) == BigInteger.ONE) {
            result = result.multiply(base).mod(modulus)
        }
        base = base.multiply(base).mod(modulus)
        exp = exp shr 1
    }
    return result
}

fun ByteVector32.toBigInteger(): BigInteger {
    return this.toByteArray().toBigInteger()
}

fun ByteArray.toBigInteger(sign: Sign = Sign.POSITIVE): BigInteger {
    return BigInteger.fromByteArray(this, sign)
}

fun BigInteger.to32LengthByteArray(): ByteArray {
    return toByteArray().toHexString().padStart(64, '0').hexToByteArray()
}

fun Int.to8LengthByteArray(): ByteArray {
    return okio.Buffer().writeLong(toLong()).readByteArray()
}

fun Int.to4LengthByteArray(): ByteArray {
    return okio.Buffer().writeInt(this).readByteArray()
}

fun Int.toSingleByteByteArray(): ByteArray {
    return byteArrayOf(toByte())
}

fun ByteArray.xor(other: ByteArray): ByteArray {
    return zip(other).map { (a,b) -> a.xor(b) }.toByteArray()
}


fun BigInteger.requireWithinCurveOrderRange(errorMessage: String = "The value is out of curve order range") {
    if (this < BigInteger.ONE || this >= CryptographicConstants.n) {
        throw IllegalArgumentException(errorMessage)
    }
}