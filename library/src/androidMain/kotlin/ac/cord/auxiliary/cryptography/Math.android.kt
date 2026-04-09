package ac.cord.auxiliary.cryptography

import java.math.BigInteger

actual fun com.ionspin.kotlin.bignum.integer.BigInteger.pow(
    exponent: com.ionspin.kotlin.bignum.integer.BigInteger,
    modulus: com.ionspin.kotlin.bignum.integer.BigInteger
): com.ionspin.kotlin.bignum.integer.BigInteger {
    val base: java.math.BigInteger = BigInteger(
        this.toByteArray()
    )
    val exponent: java.math.BigInteger = BigInteger(
        exponent.toByteArray()
    )
    val modulus: java.math.BigInteger = BigInteger(
        exponent.toByteArray()
    )

    return base.modPow(exponent, modulus).toByteArray().toBigInteger()
}