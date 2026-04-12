package ac.cord.auxiliary.cryptography

import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.lightning.utils.secure
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PrimeFieldTests {

    @Test
    fun `test FieldElement constructors`() {
        val P = FieldElement.SIZE

        val randomValidFieldElement = P.minus(
            Random.secure().nextLong(Long.MAX_VALUE)
        )
        val randomOverflowingFieldElement = P.plus(
            BigInteger.TWO.pow(256-1)
        )

        arrayOf(
            BigInteger.ZERO,
            P.minus(1),
            P,
            P.plus(1),
            randomValidFieldElement,
            randomOverflowingFieldElement
        ).forEach { initValue ->
            val fe1 = FieldElement(initValue, BigInteger.ONE)
            val fe2 = FieldElement.fromBigIntegerWrapping(initValue)
            val fe3 = FieldElement.fromBytesWrapping(initValue.toByteArray())
            val reducedValue = initValue.mod(P)

            assertEquals(fe1.toBigInteger(), reducedValue)
            assertEquals(fe1.toBigInteger(), fe2.toBigInteger())
            assertEquals(fe2.toBigInteger(), fe3.toBigInteger())
        }

        arrayOf(
            BigInteger.ZERO,
            P.minus(1),
            randomValidFieldElement
        ).forEach { validValue ->
            val fe1 = FieldElement.fromBigIntegerChecked(validValue)
            val fe2 = FieldElement.fromBytesChecked(
                validValue.toByteArray()
            )

            assertEquals(fe1.toBigInteger(), validValue)
            assertEquals(fe1.toBigInteger(), fe2.toBigInteger())

        }

        arrayOf(
            P,
            P.plus(1),
            randomOverflowingFieldElement
        ).forEach { overflowingValue ->
            assertFailsWith<IllegalArgumentException> {
                FieldElement.fromBigIntegerChecked(overflowingValue)
            }
            assertFailsWith<IllegalArgumentException> {
                FieldElement.fromBytesChecked(overflowingValue.toByteArray())
            }
        }
    }

    @Test
    fun `test Scalar constructors`() {
        val N = Scalar.SIZE
        val randomValidScalar = N.minus(
            Random.secure().nextLong(Long.MAX_VALUE)
        )
        val randomOverflowingScalar = N.plus(
            BigInteger.TWO.pow(256-1)
        )


        arrayOf(
            BigInteger.ZERO,
            N.minus(1),
            N,
            N.plus(1),
            randomValidScalar,
            randomOverflowingScalar
        ).forEach { initValue ->
            val s1 = Scalar(
                initValue,
                BigInteger.ONE
            )
            val s2 = Scalar.fromBigIntegerWrapping(initValue)
            val s3 = Scalar.fromBytesWrapping(
                initValue.toByteArray()
            )
            val reducedValue = initValue.mod(N)

            assertEquals(
                s1.toBigInteger(),
                reducedValue
            )
            assertEquals(
                s1.toBigInteger(),
                s2.toBigInteger()
            )
            assertEquals(
                s2.toBigInteger(),
                s3.toBigInteger()
            )
        }

        arrayOf(
            BigInteger.ONE,
            N.minus(1),
            randomValidScalar
        ).forEach { validValue ->
            val s1 = Scalar.fromBigIntegerChecked(validValue)
            val s2 = Scalar.fromBytesChecked(validValue.toByteArray())

            assertEquals(s1.toBigInteger(), validValue)
            assertEquals(s1.toBigInteger(), s2.toBigInteger())
        }

        arrayOf(
            N,
            N.plus(1),
            randomOverflowingScalar
        ).forEach { overflowingValue ->
            assertFailsWith<IllegalArgumentException> {
                Scalar.fromBigIntegerChecked(overflowingValue)
            }
            assertFailsWith<IllegalArgumentException> {
                Scalar.fromBytesChecked(overflowingValue.toByteArray())
            }
        }

        val randomValidNonZeroScalar = BigInteger.max(randomValidScalar, BigInteger.ONE)
        arrayOf(
            BigInteger.ONE,
            N.minus(1),
            randomValidNonZeroScalar
        ).forEach { validNonZeroScalar ->
            val s1 = Scalar.fromBigIntegerNonZeroChecked(validNonZeroScalar)
            val s2 = Scalar.fromBytesNonZeroChecked(validNonZeroScalar.toByteArray())

            assertEquals(s1.toBigInteger(), validNonZeroScalar)
            assertEquals(s2.toBigInteger(), s1.toBigInteger())

        }

        arrayOf(
            BigInteger.ZERO,
            N,
            randomOverflowingScalar
        ).forEach { invalidScalar ->
            assertFailsWith<IllegalArgumentException> {
                Scalar.fromBigIntegerNonZeroChecked(invalidScalar)
            }
            assertFailsWith<IllegalArgumentException> {
                Scalar.fromBytesNonZeroChecked(invalidScalar.toByteArray())
            }
        }

    }
}