package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.PublicKey
import fr.acinq.lightning.utils.secure
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Test-time simulations of full DKG sessions, mirroring the simulate_* helpers
 * and correctness checks of the Python reference's tests.py.
 */
object ChillDkgSimulation {

    fun randomBytes(size: Int): ByteArray = Random.secure().nextBytes(size)

    fun simulateSimplPedPop(
        seeds: List<ByteArray>,
        t: Int,
        investigation: Boolean
    ): List<Pair<DkgOutput, ByteArray>>? {
        val n = seeds.size
        val prets = (0 until n).map { i ->
            SimplPedPop.participantStep1(seeds[i], t, n, i, randomBytes(32))
        }

        val pstates = prets.map { it.first }
        val pmsgs = prets.map { it.second }

        val (cmsg, cout, ceq) = SimplPedPop.coordinatorStep(pmsgs, t, n)
        val preFinalizeRets = mutableListOf(Pair(cout, ceq))
        for (i in 0 until n) {
            val partialSecshares = prets.map { it.third[i] }.toMutableList()
            var faultyId = -1
            if (investigation) {
                // Let a random participant send incorrect shares to participant i.
                faultyId = Random.secure().nextInt(n)
                partialSecshares[faultyId] = partialSecshares[faultyId].plus(BigInteger.fromLong(17))
            }

            val secshare = SimplPedPop.participantStep2PrepareSecshare(partialSecshares)
            try {
                preFinalizeRets.add(SimplPedPop.participantStep2(pstates[i], cmsg, secshare))
            } catch (e: UnknownFaultyParticipantOrCoordinatorError) {
                if (!investigation) {
                    throw e
                }
                val invMsgs = SimplPedPop.coordinatorInvestigate(pmsgs, t)
                assertEquals(pmsgs.size, invMsgs.size)
                try {
                    SimplPedPop.participantInvestigate(e, invMsgs[i], partialSecshares)
                    // If we're not faulty, we should blame the faulty party.
                } catch (e2: FaultyParticipantOrCoordinatorError) {
                    assertTrue(i != faultyId)
                    assertEquals(faultyId, e2.participantId)
                    // If we're faulty, we'll blame the coordinator.
                } catch (e2: FaultyCoordinatorError) {
                    assertEquals(i, faultyId)
                }
                return null
            }
        }
        return preFinalizeRets
    }

    fun encpedpopKeys(seed: ByteArray): Pair<ByteArray, ByteArray> {
        val deckey = taggedHashBipDkg("encpedpop deckey", seed)
        val enckey = ChillDkgCrypto.pubkeyGenPlain(deckey)
        return Pair(deckey, enckey)
    }

    fun simulateEncPedPop(
        seeds: List<ByteArray>,
        t: Int,
        investigation: Boolean
    ): List<Pair<DkgOutput, ByteArray>>? {
        val n = seeds.size
        val encPrets0 = (0 until n).map { encpedpopKeys(seeds[it]) }

        val enckeys = encPrets0.map { it.second }
        val encPrets1 = (0 until n).map { i ->
            EncPedPop.participantStep1(seeds[i], encPrets0[i].first, enckeys, t, i, randomBytes(32))
        }

        val pstates = encPrets1.map { it.first }
        val pmsgs = encPrets1.map { it.second }.toMutableList()
        val faultyId = IntArray(n)
        if (investigation) {
            for (i in 0 until n) {
                // Let a random participant faultyId[i] send incorrect shares to
                // participant i.
                faultyId[i] = Random.secure().nextInt(n)
                val faultyPmsg = EncPedPop.ParticipantMsg.fromBytes(pmsgs[faultyId[i]], t = t, n = n)
                val faultyEncShares = faultyPmsg.encShares.mapIndexed { index, share ->
                    if (index == i) share.plus(BigInteger.fromLong(17)) else share
                }
                pmsgs[faultyId[i]] = EncPedPop.ParticipantMsg(
                    faultyPmsg.simplPmsg, faultyPmsg.pubnonce, faultyEncShares
                ).toBytes()
            }
        }

        val result = EncPedPop.coordinatorStep(pmsgs, t, enckeys)
        val preFinalizeRets = mutableListOf(Pair(result.dkgOutput, result.eqInput))
        for (i in 0 until n) {
            val deckey = encPrets0[i].first
            try {
                preFinalizeRets.add(
                    EncPedPop.participantStep2(pstates[i], deckey, result.cmsg.toBytes(), result.encSecshares[i])
                )
            } catch (e: UnknownFaultyParticipantOrCoordinatorError) {
                if (!investigation) {
                    throw e
                }
                val invMsgs = EncPedPop.coordinatorInvestigate(pmsgs, t)
                assertEquals(pmsgs.size, invMsgs.size)
                try {
                    EncPedPop.participantInvestigate(e, invMsgs[i])
                    // If we're not faulty, we should blame the faulty party.
                } catch (e2: FaultyParticipantOrCoordinatorError) {
                    assertTrue(i != faultyId[i])
                    assertEquals(faultyId[i], e2.participantId)
                    // If we're faulty, we'll blame the coordinator.
                } catch (e2: FaultyCoordinatorError) {
                    assertEquals(i, faultyId[i])
                }
                return null
            }
        }
        return preFinalizeRets
    }

    fun simulateChillDkg(
        hostseckeys: List<ByteArray>,
        t: Int,
        investigation: Boolean
    ): List<Pair<DkgOutput, ByteArray>>? {
        val n = hostseckeys.size

        val hostpubkeys = (0 until n).map { ChillDkg.hostpubkeyGen(hostseckeys[it]) }

        val params = ChillDkg.SessionParams(hostpubkeys, t)

        val prets1 = (0 until n).map { i ->
            ChillDkg.participantStep1(hostseckeys[i], params, randomBytes(32))
        }

        val pstates1 = prets1.map { it.first }
        val pmsgs = prets1.map { it.second }.toMutableList()
        val faultyId = IntArray(n)
        if (investigation) {
            for (i in 0 until n) {
                // Let a random participant faultyId[i] send incorrect shares
                // to participant i.
                faultyId[i] = Random.secure().nextInt(n)
                val faultyPmsg = ChillDkg.ParticipantMsg1.fromBytes(pmsgs[faultyId[i]], t = t, n = n)
                val faultyEncShares = faultyPmsg.encPmsg.encShares.mapIndexed { index, share ->
                    if (index == i) share.plus(BigInteger.fromLong(17)) else share
                }
                pmsgs[faultyId[i]] = ChillDkg.ParticipantMsg1(
                    EncPedPop.ParticipantMsg(
                        faultyPmsg.encPmsg.simplPmsg, faultyPmsg.encPmsg.pubnonce, faultyEncShares
                    )
                ).toBytes()
            }
        }

        val (cstate, cmsg1) = ChillDkg.coordinatorStep1(pmsgs, params)

        val prets2 = mutableListOf<Pair<ChillDkg.ParticipantState2, ByteArray>>()
        for (i in 0 until n) {
            try {
                prets2.add(ChillDkg.participantStep2(hostseckeys[i], pstates1[i], cmsg1, randomBytes(32)))
            } catch (e: UnknownFaultyParticipantOrCoordinatorError) {
                if (!investigation) {
                    throw e
                }
                val invMsgs = ChillDkg.coordinatorInvestigate(pmsgs, params)
                assertEquals(pmsgs.size, invMsgs.size)
                try {
                    ChillDkg.participantInvestigate(e, invMsgs[i])
                    // If we're not faulty, we should blame the faulty party.
                } catch (e2: FaultyParticipantOrCoordinatorError) {
                    assertTrue(i != faultyId[i])
                    assertEquals(faultyId[i], e2.participantId)
                    // If we're faulty, we'll blame the coordinator.
                } catch (e2: FaultyCoordinatorError) {
                    assertEquals(i, faultyId[i])
                }
                return null
            }
        }

        val (cmsg2, cout, crec) = ChillDkg.coordinatorFinalize(
            cstate, prets2.map { it.second }
        )
        val outputs = mutableListOf(Pair(cout, crec))
        for (i in 0 until n) {
            outputs.add(ChillDkg.participantFinalize(prets2[i].first, cmsg2))
        }

        return outputs
    }

    fun deriveInterpolatingValue(L: List<Int>, xi: Int): Scalar {
        assertTrue(xi in L)
        assertTrue(L.all { xj -> L.count { it == xj } <= 1 })
        var lam = Scalar(BigInteger.ONE)
        for (xj in L) {
            if (xj == xi) {
                continue
            }
            lam = lam.times(Scalar(xj.toBigInteger()))
                .divide(Scalar(xj.toBigInteger()).minus(Scalar(xi.toBigInteger())))
        }
        return lam
    }

    fun recoverSecret(participantIds: List<Int>, shares: List<Scalar>): Scalar {
        val interpolatedShares = mutableListOf<Scalar>()
        val t = shares.size
        assertEquals(t, participantIds.size)
        for (i in 0 until t) {
            val lam = deriveInterpolatingValue(participantIds, participantIds[i])
            interpolatedShares.add(lam.times(shares[i]))
        }
        return interpolatedShares.fold(Scalar(BigInteger.ZERO)) { acc, s -> acc.plus(s) }
    }

    fun combinations(elements: List<Int>, k: Int): List<List<Int>> {
        if (k == 0) return listOf(emptyList())
        if (elements.isEmpty()) return emptyList()
        val head = elements.first()
        val tail = elements.drop(1)
        return combinations(tail, k - 1).map { listOf(head) + it } + combinations(tail, k)
    }

    fun testCorrectnessDkgOutput(t: Int, n: Int, dkgOutputs: List<DkgOutput>) {
        assertEquals(n + 1, dkgOutputs.size)
        val secshares = dkgOutputs.map { it.secshare }
        val threshPks = dkgOutputs.map { it.threshPk }
        val pubshares = dkgOutputs.map { it.pubshares }

        // Check that the threshold pubkey and pubshares are the same for the
        // coordinator (at [0]) and all participants (at [1:n + 1]).
        for (i in 0 until n + 1) {
            assertTrue(threshPks[0].contentEquals(threshPks[i]))
            assertEquals(n, pubshares[i].size)
            assertTrue(
                pubshares[0].size == pubshares[i].size &&
                        pubshares[0].indices.all { pubshares[0][it].contentEquals(pubshares[i][it]) }
            )
        }
        val threshPk = threshPks[0]

        // Check that the coordinator has no secret share
        assertTrue(secshares[0] == null)

        // Check that each secshare matches the corresponding pubshare
        val secsharesScalar = secshares.map { it?.let { bytes -> Scalar.fromBytesChecked(bytes) } }
        for (i in 1 until n + 1) {
            val s = secsharesScalar[i]
            assertTrue(s != null)
            assertTrue(
                GroupElement.GENERATOR_POINT.mul(s.toBigInteger()) ==
                        GroupElement.fromCompressedBytes(PublicKey(pubshares[0][i - 1]))
            )
        }

        // Check that all combinations of t participants can recover the threshold pubkey
        for (tsubset in combinations((1 until n + 1).toList(), t)) {
            val recovered = recoverSecret(tsubset, tsubset.map { secsharesScalar[it]!! })
            assertTrue(
                GroupElement.GENERATOR_POINT.mul(recovered.toBigInteger()) ==
                        GroupElement.fromCompressedBytes(PublicKey(threshPk))
            )
        }
    }

    fun testCorrectness(
        t: Int,
        n: Int,
        simulateDkg: (List<ByteArray>, Int, Boolean) -> List<Pair<DkgOutput, ByteArray>>?,
        recovery: Boolean = false,
        investigation: Boolean = false
    ) {
        val seeds = listOf(null) + (0 until n).map { randomBytes(32) }

        val rets = simulateDkg(seeds.drop(1).map { it!! }, t, investigation)
        if (investigation) {
            assertTrue(rets == null)
            // The session has failed correctly, so there's nothing further to check.
            return
        }

        // rets[0] are the return values from the coordinator
        // rets[1 : n + 1] are from the participants
        assertEquals(n + 1, rets!!.size)
        val dkgOutputs = rets.map { it.first }
        testCorrectnessDkgOutput(t, n, dkgOutputs)

        val eqsOrRecs = rets.map { it.second }
        for (i in 1 until n + 1) {
            assertTrue(eqsOrRecs[0].contentEquals(eqsOrRecs[i]))
        }

        if (recovery) {
            val rec = eqsOrRecs[0]
            // Check correctness of ChillDkg.participantRecover / ChillDkg.coordinatorRecover
            for (i in 0 until n + 1) {
                val (dkgOutput, _) = if (seeds[i] == null) {
                    ChillDkg.coordinatorRecover(rec)
                } else {
                    ChillDkg.participantRecover(seeds[i]!!, rec)
                }
                val expected = dkgOutputs[i]
                if (expected.secshare == null) {
                    assertTrue(dkgOutput.secshare == null)
                } else {
                    assertTrue(dkgOutput.secshare.contentEquals(expected.secshare))
                }
                assertTrue(dkgOutput.threshPk.contentEquals(expected.threshPk))
                assertTrue(
                    dkgOutput.pubshares.size == expected.pubshares.size &&
                            dkgOutput.pubshares.indices.all { dkgOutput.pubshares[it].contentEquals(expected.pubshares[it]) }
                )
            }
        }
    }
}
