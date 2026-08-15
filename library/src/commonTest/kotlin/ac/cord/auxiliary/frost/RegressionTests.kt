package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.frost.dkg.trusted.FrostTrustedDealer
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RegressionTests {

    private val thresholdSecret = ByteVector32(Hex.decode("0000000000000000000000000000000000000000000000000000000000000042"))

    private fun soloDealership() = FrostTrustedDealer.keyGen(thresholdSecret, n = 1, t = 1)

    @Test
    fun `nonce gen pads secnonce halves to 32 bytes`() {
        // Crafted rand_ (from the reference implementation) whose first nonce hash
        // output has a leading zero byte. Minimal-length encoding used to produce a
        // 63-byte secnonce, which crashed signing.
        val rand_ = ByteVector32(Hex.decode("000000000000000000000000000000000000000000000000000000000000000d"))
        val expectedSecnonce = Hex.decode("006896c621036b9cf58d165f02cadbf9b863d47a10ca2214270080aa72a5f8f537f1774a13c90ff5b824e59607326c705aac18e2f6ce71bf9b3eb2e2d6169168")
        val expectedPubnonce = Hex.decode("02fefd4d98f4685e1ea65e6d74868aa8bc20aacddfddf891dae2ced399a12f637703d1a19ffebab974a6734015b235fe218a64ace2078463410742e4eb3bce3c90f4")

        val (secretNonce, publicNonce) = Frost.nonceGen(
            rand_ = rand_,
            secretShare = null,
            publicShare = null,
            thresholdPublicKey = null,
            message = null,
            extraIn = byteArrayOf()
        )

        assertEquals(64, secretNonce.getSecretNonce().size)
        assertContentEquals(expectedSecnonce, secretNonce.getSecretNonce())
        assertContentEquals(expectedPubnonce, publicNonce.value)

        // Signing with this secnonce must succeed.
        val dealership = soloDealership()
        val frostSignersContext = FrostSignersContext(
            n = 1,
            t = 1,
            identifiers = dealership.identifiers,
            publicShares = dealership.publicShares,
            thresholdPublicKey = dealership.thresholdPublicKey
        )
        val frostSessionContext = FrostSessionContext(
            frostSignersContext = frostSignersContext,
            aggNonce = publicNonce.value,
            tweaks = listOf(),
            isXonlies = listOf(),
            message = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        )
        val partialSignature = frostSessionContext.sign(
            secretNonce,
            dealership.secretShares.first(),
            my_id = 0
        )
        assertTrue(
            frostSessionContext.partialSignatureVerify(
                frostPartialSignature = partialSignature,
                my_id = 0,
                frostPublicNonce = publicNonce,
                publicShare = dealership.publicShares.first()
            )
        )
    }

    @Test
    fun `sign zeroizes the secret nonce and reuse throws`() {
        val dealership = soloDealership()
        val frostSignersContext = FrostSignersContext(
            n = 1,
            t = 1,
            identifiers = dealership.identifiers,
            publicShares = dealership.publicShares,
            thresholdPublicKey = dealership.thresholdPublicKey
        )
        val (secretNonce, publicNonce) = Frost.nonceGen(
            rand_ = ByteVector32(Hex.decode("0000000000000000000000000000000000000000000000000000000000000063")),
            secretShare = null,
            publicShare = null,
            thresholdPublicKey = null,
            message = null,
            extraIn = byteArrayOf()
        )
        val nonceBytesReference = secretNonce.getSecretNonce()

        val frostSessionContext = FrostSessionContext(
            frostSignersContext = frostSignersContext,
            aggNonce = publicNonce.value,
            tweaks = listOf(),
            isXonlies = listOf(),
            message = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        )
        frostSessionContext.sign(
            secretNonce,
            dealership.secretShares.first(),
            my_id = 0
        )

        // The nonce bytes have been overwritten with zeros...
        assertContentEquals(ByteArray(64), nonceBytesReference)
        // ...and the nonce can no longer be accessed or reused.
        assertFailsWith<IllegalArgumentException> {
            secretNonce.getSecretNonce()
        }
        assertFailsWith<IllegalArgumentException> {
            frostSessionContext.sign(
                secretNonce,
                dealership.secretShares.first(),
                my_id = 0
            )
        }
    }

    @Test
    fun `group element value equality`() {
        val generatorBytes = GroupElement.GENERATOR_POINT.toCompressedBytes()
        val reconstructed = GroupElement.fromCompressedBytes(generatorBytes)

        assertEquals(GroupElement.GENERATOR_POINT, reconstructed)
        assertEquals(GroupElement.GENERATOR_POINT.hashCode(), reconstructed.hashCode())

        val doubled = GroupElement.GENERATOR_POINT.add(GroupElement.GENERATOR_POINT)
        val twoTimes = GroupElement.GENERATOR_POINT.mul(com.ionspin.kotlin.bignum.integer.BigInteger.TWO)
        assertEquals(doubled, twoTimes)
        assertEquals(doubled.hashCode(), twoTimes.hashCode())

        assertEquals(GroupElement.INFINITY, GroupElement.GENERATOR_POINT.add(GroupElement.GENERATOR_POINT.negate()))
        assertFalse(GroupElement.GENERATOR_POINT == GroupElement.INFINITY)
    }

    @Test
    fun `solo deterministic sign works and verifies`() {
        val dealership = FrostTrustedDealer.keyGen(thresholdSecret, n = 3, t = 1)
        val message = Hex.decode("1100000000000000000000000000000000000000000000000000000000000011")

        // Signer with id 2 signs alone: there is no aggothernonce.
        val frostSignersContext = FrostSignersContext(
            n = 3,
            t = 1,
            identifiers = listOf(2),
            publicShares = listOf(dealership.publicShares[2]),
            thresholdPublicKey = dealership.thresholdPublicKey
        )

        val (publicNonce, partialSignature) = Frost.deterministicSign(
            secretShare = dealership.secretShares[2],
            my_id = 2,
            aggothernonce = null,
            frostSignersContext = frostSignersContext,
            tweaks = listOf(),
            isXonlies = listOf(),
            message = message,
            rand = null
        )

        val frostSessionContext = FrostSessionContext(
            frostSignersContext = frostSignersContext,
            aggNonce = publicNonce.value,
            tweaks = listOf(),
            isXonlies = listOf(),
            message = message
        )

        assertTrue(
            frostSessionContext.partialSignatureVerify(
                frostPartialSignature = partialSignature,
                my_id = 2,
                frostPublicNonce = publicNonce,
                publicShare = dealership.publicShares[2]
            )
        )

        val signature = frostSessionContext.partialSignatureAggregate(listOf(partialSignature))
        assertTrue(
            Secp256k1.verifySchnorr(
                signature = signature,
                data = message,
                pub = Frost.thresholdPublicKeyAndTweak(
                    dealership.thresholdPublicKey,
                    listOf(),
                    listOf()
                ).getXonlyPublicKey().value.toByteArray()
            ),
            "BIP340 Schnorr signature verification failed"
        )
    }

    @Test
    fun `partial signature verify accepts zero s and returns false on garbage pubnonce`() {
        val dealership = FrostTrustedDealer.keyGen(thresholdSecret, n = 2, t = 2)
        val message = Hex.decode("2200000000000000000000000000000000000000000000000000000000000022")

        val frostSignersContext = FrostSignersContext(
            n = 2,
            t = 2,
            identifiers = dealership.identifiers,
            publicShares = dealership.publicShares,
            thresholdPublicKey = dealership.thresholdPublicKey
        )

        val (secretNonce0, publicNonce0) = Frost.nonceGen(
            rand_ = ByteVector32(Hex.decode("00000000000000000000000000000000000000000000000000000000000003e7")),
            secretShare = null, publicShare = null, thresholdPublicKey = null, message = null, extraIn = byteArrayOf()
        )
        val (secretNonce1, publicNonce1) = Frost.nonceGen(
            rand_ = ByteVector32(Hex.decode("00000000000000000000000000000000000000000000000000000000000003e8")),
            secretShare = null, publicShare = null, thresholdPublicKey = null, message = null, extraIn = byteArrayOf()
        )

        val frostSessionContext = FrostSessionContext(
            frostSignersContext = frostSignersContext,
            aggNonce = Frost.nonceAgg(listOf(publicNonce0, publicNonce1)),
            tweaks = listOf(),
            isXonlies = listOf(),
            message = message
        )

        // A partial signature with s == 0 is a valid encoding (from_bytes_checked):
        // it must be parsed and fail verification, not be rejected upfront.
        assertFalse(
            frostSessionContext.partialSignatureVerify(
                frostPartialSignature = FrostPartialSignature(ByteVector32.Zeroes),
                my_id = 0,
                frostPublicNonce = publicNonce0,
                publicShare = dealership.publicShares[0]
            )
        )

        // Garbage pubnonce bytes from a malicious peer must yield false, not throw.
        val garbagePubnonce = FrostPublicNonce(byteArrayOf(0x04) + ByteArray(65))
        assertFalse(
            frostSessionContext.partialSignatureVerify(
                frostPartialSignature = FrostPartialSignature(ByteVector32.Zeroes),
                my_id = 0,
                frostPublicNonce = garbagePubnonce,
                publicShare = dealership.publicShares[0]
            )
        )

        // An out-of-range signer index is rejected by the top-level helper.
        assertFailsWith<IllegalArgumentException> {
            Frost.partialSignatureVerify(
                frostPartialSignature = FrostPartialSignature(ByteVector32.Zeroes),
                frostPublicNonces = listOf(publicNonce0, publicNonce1),
                frostSignersContext = frostSignersContext,
                tweaks = listOf(),
                isXonlies = listOf(),
                message = message,
                index = 2
            )
        }

        // Sanity check: a genuine signature verifies.
        val partialSignature = frostSessionContext.sign(secretNonce0, dealership.secretShares[0], my_id = 0)
        assertTrue(
            frostSessionContext.partialSignatureVerify(
                frostPartialSignature = partialSignature,
                my_id = 0,
                frostPublicNonce = publicNonce0,
                publicShare = dealership.publicShares[0]
            )
        )
        frostSessionContext.sign(secretNonce1, dealership.secretShares[1], my_id = 1)
    }
}
