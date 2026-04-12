package ac.cord.auxiliary.frost.trusted_dealer_keygen

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.lightning.utils.secure
import fr.acinq.secp256k1.Hex
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class FrostTrustedDealerTests {
    val testN: Int = 3
    val testT: Int = 2
    val testPoly: List<Scalar> = listOf(
        Scalar.Companion.fromBytesNonZeroChecked(
            Hex.decode("FBF85EADAE3058EA14F19148BB72B45E4399C0B16028ACAF0395C9B03C823579")
        ),
        Scalar.Companion.fromBytesNonZeroChecked(
            Hex.decode("0D004150D27C3BF2A42F312683D35FAC7394B1E9E318249C1BFE7F0795A83114")
        ),
    )
    val testSecretShares: List<Scalar> = listOf(
        Scalar.Companion.fromBytesNonZeroChecked(
            Hex.decode("08F89FFE80AC94DCB920C26F3F46140BFC7F95B493F8310F5FC1EA2B01F4254C")
        ),
        Scalar.Companion.fromBytesNonZeroChecked(
            Hex.decode("04F0FEAC2EDCEDC6CE1253B7FAB8C86B856A797F44D83D82A385554E6E401984")
        ),
        Scalar.Companion.fromBytesNonZeroChecked(
            Hex.decode("00E95D59DD0D46B0E303E500B62B7CCB0E555D49F5B849F5E748C071DA8C0DBC")
        ),
    )
    val testSecret : ByteArray = Hex.decode("0D004150D27C3BF2A42F312683D35FAC7394B1E9E318249C1BFE7F0795A83114")

    @Test
    fun `test polynomial evaluate`() {
        assertContentEquals(
            testSecret,
            FrostTrustedDealer.polynomialEvaluate(
                coefficientsWithSecret = testPoly,
                Scalar(
                    BigInteger.ZERO
                )
            ).toByteArray()
        )
    }

    @Test
    fun `test secret share combine`() {
        assertContentEquals(
            testSecret,
            FrostTrustedDealer.secretShareCombine(
                secretShares = listOf(
                    testSecretShares[0],
                    testSecretShares[1]
                ),
                identifiers = listOf(
                    0,
                    1
                )
            ).toByteArray()
        )

        assertContentEquals(
            testSecret,
            FrostTrustedDealer.secretShareCombine(
                secretShares = listOf(
                    testSecretShares[1],
                    testSecretShares[2]
                ),
                identifiers = listOf(
                    1,
                    2
                )
            ).toByteArray()
        )

        assertContentEquals(
            testSecret,
            FrostTrustedDealer.secretShareCombine(
                secretShares = listOf(
                    testSecretShares[0],
                    testSecretShares[2]
                ),
                identifiers = listOf(
                    0,
                    2
                )
            ).toByteArray()
        )

        assertContentEquals(
            testSecret,
            FrostTrustedDealer.secretShareCombine(
                secretShares = testSecretShares,
                identifiers = listOf(
                    0,
                    1,
                    2
                )
            ).toByteArray()
        )
    }

    @Test
    fun `test trusted dealer keygen`() {
        val thresholdSecretKeyBytes = Random.secure().nextBytes(32)
        val n = 5
        val t = 3

        val frostTrustedDealership = FrostTrustedDealer.keyGen(
            n = n,
            t = t,
            thresholdSecretBytes = thresholdSecretKeyBytes
        )

        val thresholdSecretKey = Scalar.fromBytesNonZeroChecked(thresholdSecretKeyBytes)
        val thresholdPublicKey = GroupElement.fromCompressedBytes(frostTrustedDealership.thresholdPublicKey)
        val secretShares = frostTrustedDealership.secretShares.map { Scalar.fromBytesNonZeroChecked(it) }
        val publicShares = frostTrustedDealership.publicShares.map { GroupElement.fromCompressedBytes(it) }

        assertContentEquals(
            thresholdPublicKey.toUncompressedBytes(),
            GroupElement.GENERATOR_POINT.mul(thresholdSecretKey.toBigInteger()).toUncompressedBytes()
        )

        assertEquals(
            thresholdSecretKey.toBigInteger(),
            FrostTrustedDealer.secretShareCombine(
                secretShares,
                (0 until n).toList()
            ).toBigInteger()
        )

        assertEquals(n, secretShares.size)
        assertEquals(n, publicShares.size)

        publicShares.forEachIndexed { index, publicShare ->
            // TODO: Subtest
            assertContentEquals(
                publicShare.toUncompressedBytes(),
                GroupElement.GENERATOR_POINT.mul(secretShares[index].toBigInteger()).toUncompressedBytes()
            )
        }
    }
}