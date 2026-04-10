package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger

class FastGroupElementMultiplication(
    groupElement: GroupElement
) {
    val logger = Logger.withTag("FastGroupElementMultiplication")
    val table= mutableListOf(groupElement)

    init {
        var point = groupElement

        for (i in 0..255) {
            logger.d("p: $point")
            point = point.add(point)

            table.add(point)
        }
    }

    companion object {
        val FAST_G = FastGroupElementMultiplication(
            GroupElement.GENERATOR_POINT
        )
    }

    fun mul(a: Scalar): GroupElement {
        return mul(a.aPrimeFE)
    }

    fun mul(a: BigInteger): GroupElement {
        var result: GroupElement = GroupElement.INFINITY

        val a_ = a
        logger.d("a_: $a")
        for (bit in 0..a.bitLength()) {
            if (a_ and (BigInteger.ONE shl  bit) == BigInteger.ONE) {
                val item = table[bit]

                result = result.add(item)
            }
        }

        logger.d("Result: $result")
        return result
    }

}