package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.secp256k1.Hex

class Scalar(
    numerator: BigInteger,
    denominator: BigInteger
): APrimeFieldElement<Scalar>(
    numerator = numerator.mod(SIZE),
    denominator = denominator.mod(SIZE),
    size = SIZE
) {

    constructor(other: Scalar): this(
        numerator = other.numerator,
        denominator = other.denominator
    )

    /**
     * This is the same as from_int_checked in bip-frost-signing
     */
    constructor(other: BigInteger): this(
        numerator = other.mod(SIZE),
        denominator = BigInteger.ONE
    ) {
        if (other >= size) {
            throw IllegalArgumentException("int ($other) is too large for from_int_checked ${size}")
        }
    }

    constructor(a: Scalar, b: Scalar): this(
        numerator = a.numerator.times(b.denominator).mod(SIZE),
        denominator = a.denominator.times(b.numerator).mod(SIZE)
    )

    constructor(a: BigInteger, b: Scalar): this(
        numerator = a.mod(SIZE).times(b.denominator).mod(SIZE),
        denominator = b.numerator.mod(SIZE)
    )

    constructor(a: Scalar, b: BigInteger): this(
        numerator = a.numerator,
        denominator = a.denominator.times(b).mod(SIZE)
    )

    override fun plus(other: Scalar): Scalar {
        return Scalar(
            numerator = this.numerator.times(other.denominator).plus(this.denominator.times(other.numerator)),
            denominator = this.denominator.times(other.denominator),
        )
    }

    override fun plus(other: BigInteger): Scalar {
        return Scalar(
            numerator = this.numerator + this.denominator.times(other),
            denominator = this.denominator,
        )
    }

    override fun minus(other: Scalar): Scalar {
        return Scalar(
            numerator = (this.numerator.times(other.denominator)).minus( this.denominator.times(other.numerator)),
            denominator = this.denominator.times(other.denominator),
        )
    }

    override fun minus(other: BigInteger): Scalar {
        return Scalar(
            numerator = this.numerator.minus(this.denominator.times(other)),
            denominator = this.denominator,
        )
    }
    override fun times(other: Scalar): Scalar {
        return Scalar(
            numerator = this.numerator.times(other.numerator),
            denominator = this.denominator.times(other.denominator),
        )
    }

    override fun times(other: BigInteger): Scalar {
        return Scalar(
            numerator = this.numerator.times(other),
            denominator = this.denominator,
        )
    }

    override fun divide(other: Scalar): Scalar {
        return Scalar(
            this,
            other
        )
    }

    override fun divide(other: BigInteger): Scalar {
        return Scalar(
            other
        )
    }

    override fun pow(other: BigInteger): Scalar {
        return Scalar(
            numerator = this.numerator.pow(other, this.size),
            denominator = this.denominator.pow(other, this.size),
        )
    }

    override fun negate(): Scalar {
        return Scalar(
            numerator = this.numerator.negate(),
            denominator = this.denominator,
        )
    }

    override fun toString(): String {
        return super.toByteArray().toHexString()
    }


    companion object {

        val logger = Logger.withTag("Scalar")

        val SIZE = Hex.decode(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        ).toBigInteger()

        fun fromBigIntegerNonZeroChecked(other: BigInteger): Scalar {
            if (other !in BigInteger.ONE..SIZE) {
                throw IllegalArgumentException("Value is out of range to be a scalar")
            }
            return Scalar(other)
        }

        fun fromBytesNonZeroChecked(other: ByteArray): Scalar {
            return fromBigIntegerNonZeroChecked(
                other.toBigInteger()
            )
        }

        fun fromBytesChecked(bytes: ByteArray): Scalar {
            val v = bytes.toBigInteger()

            return Scalar(
                v
            )
        }

        fun fromBytesWrapping(other: ByteArray): Scalar {
            return Scalar(
                other.toBigInteger().mod(SIZE)
            )
        }
    }
}
