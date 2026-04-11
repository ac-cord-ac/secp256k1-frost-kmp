package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.math.log

class FastGroupElementMultiplication(
    groupElement: GroupElement
) {
    val logger = Logger.withTag("FastGroupElementMultiplication")
    val table= mutableListOf(groupElement)

    init {
        var point = groupElement

        for (i in 0 until 255) {
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
        return mul(a.toBigInteger())
    }

    fun mul(a: BigInteger): GroupElement {
        var result: GroupElement = GroupElement.INFINITY

        for (bit in 0..a.bitLength()) {
            if (a and (BigInteger.ONE shl  bit) != BigInteger.ZERO) {
                val item = table[bit]

                result = result.add(item)
            }
        }

        return result
    }

}