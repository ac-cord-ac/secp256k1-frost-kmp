package ac.cord.auxiliary.cryptography

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.secp256k1.Hex
import kotlin.math.log

data class GroupElement(
    private val x: FieldElement,
    private val y: FieldElement,
    var isInfinity: Boolean = false, // TODO: Make this private...
) {
    companion object {
        private val logger = Logger.withTag("GroupElement")

        val ORDER = Scalar.SIZE
        val ORDER_HALF = ORDER.floorDiv(BigInteger.TWO)

        val INFINITY = GroupElement(
            x = FieldElement(BigInteger.ZERO),
            y = FieldElement(BigInteger.ZERO),
            isInfinity = true
        )

        val GENERATOR_POINT = liftX(
            Hex.decode(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            ).toBigInteger()
        )

        fun liftX(x: FieldElement): GroupElement {
            return liftX(
                x.toBigInteger()
            )
        }

        fun liftX(x: BigInteger): GroupElement {
            val power = FieldElement(x).pow(3.toBigInteger())
            val plus7 = power.plus(7.toBigInteger())
            val y = FieldElement(plus7.toBigInteger()).sqrt()

            if (y == null) {
                throw IllegalArgumentException("We couldn't compute y")
            }

            return GroupElement(
                x = FieldElement(x),
                y = if (!y.isEven()) {
                    val negation  = FieldElement(
                        y.negate().toBigInteger()
                    )

                    negation
                } else {
                    y
                }
            )
        }

        fun fromCompressedBytes(compressedBytes: PublicKey): GroupElement {
            if (compressedBytes.value[0] != 2.toByte() && compressedBytes.value[0] != 3.toByte()) {
                throw IllegalArgumentException("First byte of the compressedBytes is not what is expected")
            }
            val slice = compressedBytes.value.toByteArray().sliceArray(1..32)
            val x = FieldElement.fromBytesChecked(slice)

            val r = liftX(x)
            return if (compressedBytes.value[0] == 3.toByte()) {
                r.negate()
            } else {
                r
            }
        }

        fun fromCompressedBytesWithInfinity(compressedBytes: PublicKey): GroupElement {
            return if (compressedBytes.value.toByteArray().contentEquals(ByteArray(33))) { // TODO: Find a better way to do this...
                INFINITY
            } else {
                fromCompressedBytes(compressedBytes)
            }
        }

        fun batchMul(vararg aps: Pair<Scalar, GroupElement>): GroupElement {
            val naps: List<Pair<BigInteger, GroupElement>> = aps.map { (a, p) ->
                Pair(
                    a.toBigInteger(),
                    p
                )
            }

            var r = INFINITY
            for (i in 255 downTo 0) {
                r = r.add(r)
                naps.forEach { (a, p) ->
                    if ((a shr i) and BigInteger.ONE == BigInteger.ONE) {
                        r = r.add(p)
                    }
                }
            }

            return r
        }
    }

    fun negate(): GroupElement {
        if (isInfinity) {
            return this
        }

        return GroupElement(
            x= this.x,
            y = FieldElement(this.y.negate().toBigInteger())
        )
    }

    fun getX(): FieldElement {
        require(!isInfinity)
        return x
    }

    fun getY(): FieldElement {
        require(!isInfinity)
        return y
    }

    fun add(other: GroupElement): GroupElement {
        if (this.isInfinity) {
            return other
        }

        if (other.isInfinity) {
            return this
        }

        val lam: FieldElement? = if (this.x.toBigInteger() ==  other.x.toBigInteger()) {
            if (this.y.toBigInteger() != other.y.toBigInteger()) {
                require(this.y.plus(other.y).toBigInteger() == BigInteger.ZERO) { "A point added to its own negation is infinity." }

                return INFINITY
            } else {
                x.pow(BigInteger.TWO).times(3.toBigInteger()).divide(y.times(BigInteger.TWO))
            }
        } else {

            val yminusy = y.minus(other.y)
            val xminusx = x.minus(other.x)

            yminusy.divide(xminusx)
        }

        if (lam == null) {
            return INFINITY
        } else {
            val tempX = lam.pow(BigInteger.TWO).minus(this.x.plus(other.x))
            val tempY = lam.times(this.x.minus(tempX)).minus(this.y)

            return GroupElement(
                x = tempX,
                y = tempY
            )
        }
    }

    fun hasEvenY(): Boolean {
        require(!isInfinity) { "Required to not be at infinity" }
        return this.y.isEven()
    }

    fun toCompressedBytes(): PublicKey {
        require(!isInfinity) { "Required to not be at infinity" }
        val a = if (hasEvenY()) {
            byteArrayOf(0x02)
        } else {
            byteArrayOf(0x03)
        }
        return PublicKey(
            a + x.toByteArray()
        )
    }

    fun toCompressedBytesWithInfinity(): PublicKey {
        if (isInfinity) {
            return PublicKey(
                byteArrayOf(0x00) + ByteVector32.Zeroes.toByteArray()
            )
        }
        return toCompressedBytes()
    }

    fun toUncompressedBytes(): ByteArray {
        require(!isInfinity) { "Required to not be at infinity" }

        return byteArrayOf(0x04) + x.toByteArray() + y.toByteArray()
    }

    fun toXonlyPublicKey(): XonlyPublicKey {
        require(!isInfinity) { "Required to not be at infinity" }
        return XonlyPublicKey(
            ByteVector32(
                x.toByteArray()
            )
        )
    }

    fun mul(other: BigInteger): GroupElement {
        if (this == GENERATOR_POINT) {
            return FastGroupElementMultiplication.FAST_G.mul(Scalar(other))
        }

        return batchMul(
            Pair(
                Scalar(other),
                this
            )
        )
    }

    override fun toString(): String {
        return "($x, $y, $isInfinity)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as GroupElement

        if (isInfinity != other.isInfinity) return false
        if (x != other.x) return false
        if (y != other.y) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isInfinity.hashCode()
        result = 31 * result + x.hashCode()
        result = 31 * result + y.hashCode()
        return result
    }


}