package ac.cord.auxiliary.cryptography

import com.ionspin.kotlin.bignum.integer.BigInteger

open class APrimeFieldElement(
    var numerator: BigInteger,
    var denominator: BigInteger,
    val size: BigInteger
) {
    init {
        require(denominator != BigInteger.ZERO) { "Denominator cannot be ZERO" }
        if (numerator == BigInteger.ZERO) {
            denominator = BigInteger.ONE
        }
    }
    fun toBigInteger(): BigInteger {
        if (this.denominator != BigInteger.ONE) {
            this.numerator = this.numerator.times(this.denominator.pow(BigInteger.ONE.negate(), this.size)).mod(this.size)
            this.denominator = BigInteger.ONE
        }

        return this.numerator
    }

    fun plus(other: APrimeFieldElement): APrimeFieldElement {
        return APrimeFieldElement(
            numerator = this.numerator.times(other.denominator) + this.denominator.times(other.numerator),
            denominator = this.denominator.times(other.denominator),
            size = this.size
        )
    }

    fun plus(other: BigInteger): APrimeFieldElement {
        return APrimeFieldElement(
            numerator = this.numerator + this.denominator.times(other),
            denominator = this.denominator,
            size = this.size
        )
    }

    fun pow(other: BigInteger): APrimeFieldElement {
        return APrimeFieldElement(
            numerator = this.numerator.pow(other, this.size),
            denominator = this.denominator.pow(other, this.size),
            size = this.size
        )
    }

    fun negate(): APrimeFieldElement {
        return APrimeFieldElement(
            numerator = this.numerator.negate(),
            denominator = this.denominator,
            size = this.size
        )
    }

    fun isEven(): Boolean {
        return toBigInteger() and BigInteger.ONE == BigInteger.ONE
    }

    fun toByteArray(): ByteArray {
        return toBigInteger().to32LengthByteArray()
    }

    override fun toString(): String {
        return toByteArray().toHexString()
    }

}