package ac.cord.auxiliary.cryptography

import java.math.BigInteger
import kotlin.math.exp


actual fun com.ionspin.kotlin.bignum.integer.BigInteger.pow(
    exponent: com.ionspin.kotlin.bignum.integer.BigInteger,
    modulus: com.ionspin.kotlin.bignum.integer.BigInteger
): com.ionspin.kotlin.bignum.integer.BigInteger {
    val base = BigInteger(
        this.signum(),
        this.toByteArray()
    )
    val exponent = BigInteger(
        exponent.signum(),
        exponent.toByteArray()
    )
    val modulus = BigInteger(
        modulus.signum(),
        modulus.toByteArray()
    )

    return base.modPow(exponent, modulus).toByteArray().toBigInteger()
}