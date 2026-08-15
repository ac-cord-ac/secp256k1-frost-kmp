package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.toBigInteger
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Port of the non-vector tests of the Python reference's tests.py.
 */
class ChillDkgCorrectnessTests {

    @Test
    fun `test chilldkg params validate`() {
        val hostseckeys = (0 until 3).map { ChillDkgSimulation.randomBytes(32) }
        val hostpubkeys = hostseckeys.map { ChillDkg.hostpubkeyGen(it) }

        val withDuplicate = listOf(hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1])
        val paramsWithDuplicate = ChillDkg.SessionParams(withDuplicate, 2)
        val duplicateError = assertFailsWith<ChillDkg.DuplicateHostPubkeyError> {
            ChillDkg.paramsHash(paramsWithDuplicate)
        }
        assertEquals(setOf(1, 3), setOf(duplicateError.participantId1, duplicateError.participantId2))

        val invalidHostpubkey = byteArrayOf(0x03) + ByteArray(31) + byteArrayOf(0x05) // Invalid x-coordinate
        val paramsWithInvalid = ChillDkg.SessionParams(
            listOf(hostpubkeys[1], invalidHostpubkey, hostpubkeys[2]), 1
        )
        val invalidError = assertFailsWith<ChillDkg.InvalidHostPubkeyError> {
            ChillDkg.paramsHash(paramsWithInvalid)
        }
        assertEquals(1, invalidError.participantId)

        assertFailsWith<ChillDkg.ThresholdOrCountError> {
            ChillDkg.paramsHash(ChillDkg.SessionParams(hostpubkeys, hostpubkeys.size + 1))
        }

        assertFailsWith<ChillDkg.ThresholdOrCountError> {
            ChillDkg.paramsHash(ChillDkg.SessionParams(hostpubkeys, -2))
        }
    }

    @Test
    fun `test vss correctness`() {
        fun randPolynomial(t: Int): Polynomial {
            return Polynomial((1..t).map {
                // randint(1, GE.ORDER - 1)
                val coeff = ChillDkgSimulation.randomBytes(32).toBigInteger()
                    .mod(GroupElement.ORDER.minus(BigInteger.ONE)).plus(BigInteger.ONE)
                Scalar(coeff)
            })
        }

        for (t in 1 until 3) {
            for (n in t until 2 * t + 1) {
                val f = randPolynomial(t)
                val vss = Vss(f)
                val secshares = vss.secshares(n)
                assertEquals(n, secshares.size)
                assertTrue(
                    (0 until n).all { i ->
                        VssCommitment.verifySecshare(secshares[i], vss.commit().pubshare(i))
                    }
                )

                val (vsscTweaked, tweak, pubtweak) = vss.commit().invalidTaprootCommit()
                assertTrue(
                    VssCommitment.verifySecshare(
                        vss.secret().plus(tweak),
                        vss.commit().commitmentToSecret().add(pubtweak)
                    )
                )
                assertTrue(
                    (0 until n).all { i ->
                        VssCommitment.verifySecshare(
                            secshares[i].plus(tweak), vsscTweaked.pubshare(i)
                        )
                    }
                )
            }
        }
    }

    @Test
    fun `test recover secret`() {
        val f = Polynomial(listOf(23, 42).map { Scalar(it.toBigInteger()) })
        val shares = listOf(1, 2, 3).map { f.eval(Scalar(it.toBigInteger())) }
        assertTrue(ChillDkgSimulation.recoverSecret(listOf(1, 2), listOf(shares[0], shares[1])) == f.coeffs[0])
        assertTrue(ChillDkgSimulation.recoverSecret(listOf(1, 3), listOf(shares[0], shares[2])) == f.coeffs[0])
        assertTrue(ChillDkgSimulation.recoverSecret(listOf(2, 3), listOf(shares[1], shares[2])) == f.coeffs[0])
    }

    @Test
    fun `test correctness simplpedpop`() {
        for ((t, n) in listOf(1 to 1, 1 to 2, 2 to 2, 2 to 3, 2 to 5)) {
            ChillDkgSimulation.testCorrectness(t, n, ChillDkgSimulation::simulateSimplPedPop)
        }
    }

    @Test
    fun `test correctness simplpedpop investigation`() {
        for ((t, n) in listOf(1 to 1, 1 to 2, 2 to 2, 2 to 3, 2 to 5)) {
            ChillDkgSimulation.testCorrectness(t, n, ChillDkgSimulation::simulateSimplPedPop, investigation = true)
        }
    }

    @Test
    fun `test correctness encpedpop`() {
        for ((t, n) in listOf(1 to 1, 1 to 2, 2 to 2, 2 to 3, 2 to 5)) {
            ChillDkgSimulation.testCorrectness(t, n, ChillDkgSimulation::simulateEncPedPop)
        }
    }

    @Test
    fun `test correctness encpedpop investigation`() {
        for ((t, n) in listOf(1 to 1, 1 to 2, 2 to 2, 2 to 3, 2 to 5)) {
            ChillDkgSimulation.testCorrectness(t, n, ChillDkgSimulation::simulateEncPedPop, investigation = true)
        }
    }

    @Test
    fun `test correctness chilldkg recovery`() {
        for ((t, n) in listOf(1 to 1, 1 to 2, 2 to 2, 2 to 3, 2 to 5)) {
            ChillDkgSimulation.testCorrectness(t, n, ChillDkgSimulation::simulateChillDkg, recovery = true)
        }
    }

    @Test
    fun `test correctness chilldkg recovery investigation`() {
        for ((t, n) in listOf(1 to 1, 1 to 2, 2 to 2, 2 to 3, 2 to 5)) {
            ChillDkgSimulation.testCorrectness(t, n, ChillDkgSimulation::simulateChillDkg, recovery = true, investigation = true)
        }
    }

    @Test
    fun `test recovery acknowledgment`() {
        val t = 2
        val n = 3
        val hostseckeys = (0 until n).map { ChillDkgSimulation.randomBytes(32) }
        val hostpubkeys = hostseckeys.map { ChillDkg.hostpubkeyGen(it) }
        val params = ChillDkg.SessionParams(hostpubkeys, t)

        val results = ChillDkgSimulation.simulateChillDkg(hostseckeys, t, investigation = false)!!
        val recoveryData = results[1].second // First participant's recovery data

        val ackSigs = mutableListOf<ByteArray>()
        for (i in 0 until n) {
            val ackSig = ChillDkg.participantRecoveryAckSign(
                hostseckeys[i], recoveryData, params, ChillDkgSimulation.randomBytes(32)
            )
            assertEquals(64, ackSig.size)
            ackSigs.add(ackSig)
        }

        ChillDkg.participantRecoveryAcksVerify(recoveryData, params, ackSigs)

        // Wrong hostseckey length
        assertFailsWith<IllegalArgumentException> {
            ChillDkg.participantRecoveryAckSign(
                ChillDkgSimulation.randomBytes(16), recoveryData, params, ChillDkgSimulation.randomBytes(32)
            )
        }

        // Invalid hostpubkey in params
        val invalidHostpubkey = byteArrayOf(0x03) + ByteArray(31) + byteArrayOf(0x05)
        val invalidParams = ChillDkg.SessionParams(listOf(hostpubkeys[0], invalidHostpubkey), t)
        assertFailsWith<ChillDkg.InvalidHostPubkeyError> {
            ChillDkg.participantRecoveryAckSign(
                hostseckeys[0], recoveryData, invalidParams, ChillDkgSimulation.randomBytes(32)
            )
        }

        assertFailsWith<ChillDkg.InvalidHostPubkeyError> {
            ChillDkg.participantRecoveryAcksVerify(recoveryData, invalidParams, ackSigs)
        }

        // Duplicate hostpubkey in params
        val duplicateParams = ChillDkg.SessionParams(listOf(hostpubkeys[0], hostpubkeys[0]), t)
        assertFailsWith<ChillDkg.DuplicateHostPubkeyError> {
            ChillDkg.participantRecoveryAckSign(
                hostseckeys[0], recoveryData, duplicateParams, ChillDkgSimulation.randomBytes(32)
            )
        }

        // Invalid threshold in params
        val invalidThresholdParams = ChillDkg.SessionParams(hostpubkeys, n + 1)
        assertFailsWith<ChillDkg.ThresholdOrCountError> {
            ChillDkg.participantRecoveryAckSign(
                hostseckeys[0], recoveryData, invalidThresholdParams, ChillDkgSimulation.randomBytes(32)
            )
        }

        // Wrong hostseckey
        assertFailsWith<ChillDkg.HostSeckeyError> {
            ChillDkg.participantRecoveryAckSign(
                ChillDkgSimulation.randomBytes(32), recoveryData, params, ChillDkgSimulation.randomBytes(32)
            )
        }

        // Invalid randomness length
        assertFailsWith<IllegalArgumentException> {
            ChillDkg.participantRecoveryAckSign(
                hostseckeys[0], recoveryData, params, ChillDkgSimulation.randomBytes(16)
            )
        }

        // Mismatched params
        val mismatchedParams = ChillDkg.SessionParams(hostpubkeys, t + 1)
        assertFailsWith<ChillDkg.RecoveryDataError> {
            ChillDkg.participantRecoveryAckSign(
                hostseckeys[0], recoveryData, mismatchedParams, ChillDkgSimulation.randomBytes(32)
            )
        }

        assertFailsWith<ChillDkg.RecoveryDataError> {
            ChillDkg.participantRecoveryAcksVerify(recoveryData, mismatchedParams, ackSigs)
        }

        // Corrupted recovery data
        val corruptedRecoveryData = ChillDkgSimulation.randomBytes(recoveryData.size)
        assertFailsWith<ChillDkg.RecoveryDataError> {
            ChillDkg.participantRecoveryAckSign(
                hostseckeys[0], corruptedRecoveryData, params, ChillDkgSimulation.randomBytes(32)
            )
        }

        assertFailsWith<ChillDkg.RecoveryDataError> {
            ChillDkg.participantRecoveryAcksVerify(corruptedRecoveryData, params, ackSigs)
        }

        // Invalid signature
        val invalidAckSigs = ackSigs.toMutableList()
        invalidAckSigs[1] = ChillDkgSimulation.randomBytes(64)
        val invalidRecoveryAckError = assertFailsWith<ChillDkg.InvalidRecoveryAckError> {
            ChillDkg.participantRecoveryAcksVerify(recoveryData, params, invalidAckSigs)
        }
        assertEquals(1, invalidRecoveryAckError.participantId)

        // Wrong signature length
        val wrongLengthSigs = ackSigs.toMutableList()
        wrongLengthSigs[0] = ChillDkgSimulation.randomBytes(32)
        assertFailsWith<IllegalArgumentException> {
            ChillDkg.participantRecoveryAcksVerify(recoveryData, params, wrongLengthSigs)
        }

        // Wrong number of signatures
        val wrongCountSigs = ackSigs.dropLast(1) // n-1 instead of n
        assertFailsWith<IllegalArgumentException> {
            ChillDkg.participantRecoveryAcksVerify(recoveryData, params, wrongCountSigs)
        }
    }
}
