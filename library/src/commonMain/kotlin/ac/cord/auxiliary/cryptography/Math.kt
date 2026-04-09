package ac.cord.auxiliary.cryptography

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import ac.cord.auxiliary.cryptography.CryptographicConstants.p
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

//fun BigInteger.pow(exponent: BigInteger, modulus: BigInteger): BigInteger {
//    Logger.d("${this}.pow($exponent)%${modulus}")
//    val pow = this.pow(exponent)
//    Logger.d("Pow: $pow")
//    val mod = pow.mod(modulus)
//    Logger.d("Mod: $mod")
//    return mod
//}

expect fun BigInteger.pow(exponent: BigInteger, modulus: BigInteger): BigInteger

fun ByteVector32.toBigInteger(): BigInteger {
    return this.toByteArray().toBigInteger()
}

fun ByteArray.toBigInteger(sign: Sign = Sign.POSITIVE): BigInteger {
    return BigInteger.fromByteArray(this, sign)
}

fun ByteArray.liftX(): Point? {
    return toBigInteger().liftX()
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

fun BigInteger.liftX(): Point? {
    val x = this

    if (x > p) {
        return null
    }

    val ySq = x.pow(3.toBigInteger(), p).plus(7).mod(p)
    val y = ySq.pow(p.plus(1).floorDiv(4.toBigInteger()), p)

    if (y.pow(BigInteger.TWO, p) != ySq) {
        return null
    }

    return Point(
        x = x,
        y = if (y and BigInteger.ONE == BigInteger.ZERO) {
            y
        } else {
            p.minus(y)
        }
    )
}

fun ByteArray.xor(other: ByteArray): ByteArray {
    return zip(other).map { (a,b) -> a.xor(b) }.toByteArray()
}


fun BigInteger.requireWithinCurveOrderRange(errorMessage: String = "The value is out of curve order range: $this") {
    if (this <= 0 || this > CryptographicConstants.n) {
        throw IllegalArgumentException(errorMessage)
    }
}