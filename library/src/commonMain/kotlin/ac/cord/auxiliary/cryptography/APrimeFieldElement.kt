package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger

abstract class APrimeFieldElement<T>(
    var numerator: BigInteger,
    var denominator: BigInteger,
    val size: BigInteger,
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

    abstract fun plus(other: T): T

    abstract fun plus(other: BigInteger): T


    abstract fun minus(other: T): T

    abstract fun minus(other: BigInteger): T

    abstract fun times(other: T): T

    abstract fun times(other: BigInteger): T

    abstract fun divide(other: T): T

    abstract fun divide(other: BigInteger): T


    abstract fun pow(other: BigInteger): T

    abstract fun negate(): T

    fun isEven(): Boolean {
        return toBigInteger() and BigInteger.ONE == BigInteger.ZERO
    }

    fun toByteArray(): ByteArray {
        return toBigInteger().to32LengthByteArray()
    }

    override fun toString(): String {
        return toByteArray().toHexString()
    }
}