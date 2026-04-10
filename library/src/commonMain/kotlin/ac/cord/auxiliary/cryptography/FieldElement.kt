package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger

class FieldElement(
    aPrimeFE: BigInteger
): APrimeFieldElement(
    numerator = aPrimeFE.mod(SIZE),
    denominator = BigInteger.ONE,
    size = SIZE
) {
    companion object {
        val logger = Logger.withTag("FieldElement")

        val SIZE: BigInteger = BigInteger.TWO.pow(256).minus(
            BigInteger.TWO.pow(32)
        ).minus(977)

        fun fromBytesChecked(bytes: ByteArray): FieldElement {
            logger.d("slice: ${bytes.toHexString()}")
            val v = bytes.toBigInteger()
            logger.d("v: $v")

            return FieldElement(
                v
            )
        }
    }

    fun sqrt(): FieldElement? {
        val v = this.toBigInteger()

        logger.d("sqrt: $v")
        val s = v.pow(
            (SIZE + 1).floorDiv(4.toBigInteger()),
            SIZE
        )

        logger.d("s: $s")
        if (s.pow(2).mod(SIZE) == v) {
            return FieldElement(
                s
            )
        }
        return null
    }

    override fun toString(): String {
        return super.toByteArray().toHexString()
    }
}