package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger

abstract class APrimeFieldElement<T>(
    val numerator: BigInteger,
    val denominator: BigInteger,
    val size: BigInteger,
) {
    init {
        require(denominator != BigInteger.ZERO) { "Denominator cannot be ZERO" }
    }

    fun toBigInteger(): BigInteger {
        if (this.denominator == BigInteger.ONE) {
            return this.numerator
        }

        return this.numerator.times(this.denominator.pow(BigInteger.ONE.negate(), this.size)).mod(this.size)
    }

    abstract fun plus(other: T): T

    abstract fun plus(other: BigInteger): T


    abstract fun minus(other: T): T

    abstract fun minus(other: BigInteger): T

    abstract fun times(other: T): T

    abstract fun times(other: BigInteger): T

    abstract fun divide(other: T): T

    abstract fun pow(other: BigInteger): T

    abstract fun negate(): T

    fun isEven(): Boolean {
        return toBigInteger() and BigInteger.ONE == BigInteger.ZERO
    }

    fun toByteArray(): ByteArray {
        return toBigInteger().to32LengthByteArray()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as APrimeFieldElement<*>

        // Cross-multiplication compares the values without a modular inversion.
        return size == other.size &&
                numerator.times(other.denominator).mod(size) == other.numerator.times(denominator).mod(size)
    }

    override fun hashCode(): Int {
        return 31 * size.hashCode() + toBigInteger().hashCode()
    }

    override fun toString(): String {
        return toByteArray().toHexString()
    }
}