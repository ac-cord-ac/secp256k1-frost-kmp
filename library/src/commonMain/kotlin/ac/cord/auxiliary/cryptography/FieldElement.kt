package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger

class FieldElement(
    numerator: BigInteger,
    denominator: BigInteger
): APrimeFieldElement<FieldElement>(
    numerator = numerator.mod(SIZE),
    denominator = denominator.mod(SIZE),
    size = SIZE
) {

    constructor(other: FieldElement): this(
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
            throw IllegalArgumentException("int ($numerator) is too large for from_int_checked")
        }
    }

    constructor(a: FieldElement, b: FieldElement): this(
        numerator = a.numerator.times(b.denominator).mod(SIZE),
        denominator = a.denominator.times(b.numerator).mod(SIZE)
    )

    constructor(a: BigInteger, b: FieldElement): this(
        numerator = a.mod(SIZE).times(b.denominator).mod(SIZE),
        denominator = b.numerator.mod(SIZE)
    )

    constructor(a: FieldElement, b: BigInteger): this(
        numerator = a.numerator,
        denominator = a.denominator.times(b).mod(SIZE)
    )


    fun sqrt(): FieldElement? {
        val v = this.toBigInteger()

        val s = v.pow(
            (SIZE + 1).floorDiv(4.toBigInteger()),
            SIZE
        )

        if (s.pow(2).mod(SIZE) == v) {
            return FieldElement(
                s
            )
        }
        return null
    }

    override fun plus(other: FieldElement): FieldElement {
        return FieldElement(
            numerator = this.numerator.times(other.denominator).plus(this.denominator.times(other.numerator)),
            denominator = this.denominator.times(other.denominator),
        )
    }

    override fun plus(other: BigInteger): FieldElement {
        return FieldElement(
            numerator = this.numerator + this.denominator.times(other),
            denominator = this.denominator,
        )
    }

    override fun minus(other: FieldElement): FieldElement {
        return FieldElement(
            numerator = (this.numerator.times(other.denominator)).minus( this.denominator.times(other.numerator)),
            denominator = this.denominator.times(other.denominator),
        )
    }

    override fun minus(other: BigInteger): FieldElement {
        return FieldElement(
            numerator = this.numerator.minus(this.denominator.times(other)),
            denominator = this.denominator,
        )
    }
    override fun times(other: FieldElement): FieldElement {
        return FieldElement(
            numerator = this.numerator.times(other.numerator),
            denominator = this.denominator.times(other.denominator),
        )
    }

    override fun times(other: BigInteger): FieldElement {
        return FieldElement(
            numerator = this.numerator.times(other),
            denominator = this.denominator,
        )
    }

    override fun divide(other: FieldElement): FieldElement {
        return FieldElement(
            this,
            other
        )
    }

    override fun divide(other: BigInteger): FieldElement {
        return FieldElement(
            other
        )
    }

    override fun pow(other: BigInteger): FieldElement {
        return FieldElement(
            numerator = this.numerator.pow(other, this.size),
            denominator = this.denominator.pow(other, this.size),
        )
    }

    override fun negate(): FieldElement {
        return FieldElement(
            numerator = this.numerator.negate(),
            denominator = this.denominator,
        )
    }

    override fun toString(): String {
        return super.toByteArray().toHexString()
    }


    companion object {
        val logger = Logger.withTag("FieldElement")

        val SIZE: BigInteger = BigInteger.TWO.pow(256).minus(
            BigInteger.TWO.pow(32)
        ).minus(977)

        fun fromBytesChecked(bytes: ByteArray): FieldElement {
            val v = bytes.toBigInteger()

            return FieldElement(
                v
            )
        }
    }

}