package ac.cord.auxiliary.cryptography

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.times
import ac.cord.auxiliary.cryptography.CryptographicConstants.p
import co.touchlab.kermit.Logger
import fr.acinq.secp256k1.Hex

open class Point(
    private val x: BigInteger,
    private val y: BigInteger,
) {
    companion object {

        val logger = Logger.withTag("Point")

        val G = Point(
            x = Hex.decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").toBigInteger(),
            y = Hex.decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").toBigInteger()
        )

        fun fromCompressedBytes(x: ByteArray): Point {
            if (x.size != 33) {
                throw IllegalArgumentException("x is not a valid compressed point.")
            }
            val slice = x.sliceArray(1..32)
            val point = slice.liftX() ?: throw IllegalArgumentException("x is not a valid compressed point")

            return if (x[0] == 2.toByte()) {
                point
            } else if (x[0] == 3.toByte()) {
                point.negate()
            } else {
                throw IllegalArgumentException("x is not a valid compressed point")
            }
        }

        fun fromCompressedBytesExt(x: ByteArray): Point? {
            return if (x.contentEquals("000000000000000000000000000000000000000000000000000000000000000000".hexToByteArray())) {
                null
            } else {
                fromCompressedBytes(x)
            }
        }
    }
    private val isInfinite: Boolean = false

    fun getX(): BigInteger {
        require(!isInfinite)
        return x
    }

    fun getY(): BigInteger {
        require(!isInfinite)
        return y
    }

    private fun lam(other: Point): BigInteger {
        return if (this == other) {
            val intermediary = (BigInteger.TWO.times(this.getY()).pow(p - 2, p))
            3.times(this.getX()).times(this.getX()).times(intermediary).mod(p)
        } else {
            val intermediary = other.getX().minus(this.getX()).pow(p - 2, p)
            other.getY().minus(this.getY()).times(intermediary).mod(p)
        }
    }

    fun add(other: Point?): Point? {
        if (other == null) {
            return this
        }

        if (this.getX() == other.getX() && (this.getY() != other.getY())) {
            return null
        }

        val lam = lam(other)

        val x3 = (lam.times(lam).minus(this.getX()).minus(other.getX())).mod(p)
        return Point(
            x = x3,
            y = lam.times(this.getX().minus(x3)).minus(this.getY()).mod(p)
        )
    }

    fun mul(n: BigInteger): Point? {
        var result: Point? = null
        var tempPoint = this
        for (i in 0 until 256) {
            val testBit = n.shr(i).and(BigInteger.ONE) == BigInteger.ONE
            if (testBit) {
                result = result?.add(tempPoint) ?: tempPoint
            }
            tempPoint = tempPoint.add(tempPoint)!!
        }
        return result
    }


    fun hasEvenY(): Boolean {
        require(!isInfinite) // TODO: Have a better way of dealing with this...
        return getY().mod(BigInteger.TWO) == BigInteger.ZERO
    }

    fun xbytes(): ByteArray {
        return getX().toByteArray()
    }

    fun cbytes(): ByteArray {
        val a = if (hasEvenY()) {
            byteArrayOf(0x02)
        } else {
            byteArrayOf(0x03)
        }

        return a + xbytes()
    }

    fun cbytesExt(): ByteArray {
        if (isInfinite) {
            BigInteger.ZERO.toByteArray()
        }
        return cbytes()
    }

    fun negate(): Point {
        return Point(
            x = getX(),
            y = p - getY()
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Point

        if (isInfinite != other.isInfinite) return false
        if (x != other.x) return false
        if (y != other.y) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isInfinite.hashCode()
        result = 31 * result + x.hashCode()
        result = 31 * result + y.hashCode()
        result = 31 * result + logger.hashCode()
        return result
    }

    override fun toString(): String {
        return "($x, $y)"
    }

}