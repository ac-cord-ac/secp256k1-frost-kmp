package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.bitcoin.PublicKey

/**
 * Sum of scalars, identical to Scalar.sum(...) in the Python reference.
 */
internal fun Iterable<Scalar>.scalarSum(): Scalar = fold(Scalar(BigInteger.ZERO)) { acc, s -> acc.plus(s) }

/**
 * Sum of group elements, identical to GE.sum(...) in the Python reference.
 */
internal fun Iterable<GroupElement>.geSum(): GroupElement = fold(GroupElement.INFINITY) { acc, p -> acc.add(p) }

/**
 * Holds the outputs of a DKG session.
 *
 * [secshare]: secret share of the participant (32 bytes, or null for the coordinator).
 * [threshPk]: generated threshold public key representing the group (33 bytes, compressed).
 * [pubshares]: public shares of the participants (33 bytes each, compressed).
 */
class DkgOutput(
    val secshare: ByteArray?,
    val threshPk: ByteArray,
    val pubshares: List<ByteArray>
)

/**
 * SimplPedPop: a simple Pedersen DKG with proofs of possession, where secret
 * shares are distributed via external secure channels. Ported from
 * chilldkg_ref/simplpedpop.py.
 */
object SimplPedPop {

    class SecshareSumError(message: String? = null) : IllegalArgumentException(message)

    ///
    /// Proofs of possession (pops)
    ///

    private const val POP_MSG_TAG = BIP_TAG + "pop message"

    private fun popMsg(participantId: Int): ByteArray = participantId.to4LengthByteArray()

    fun popProve(seckey: ByteArray, participantId: Int, auxRand: ByteArray): ByteArray {
        return ChillDkgCrypto.schnorrSign(popMsg(participantId), seckey, auxRand, tagPrefix = POP_MSG_TAG)
    }

    fun popVerify(pop: ByteArray, pubkey: ByteArray, participantId: Int): Boolean {
        return ChillDkgCrypto.schnorrVerify(popMsg(participantId), pubkey, pop, tagPrefix = POP_MSG_TAG)
    }

    ///
    /// Messages
    ///

    class ParticipantMsg(val com: VssCommitment, val pop: ByteArray) {
        fun toBytes(): ByteArray = com.toBytes() + pop

        companion object {
            fun lenBytes(t: Int): Int = 33 * t + 64

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, t: Int): ParticipantMsg {
                if (b.size != lenBytes(t)) {
                    throw IllegalArgumentException()
                }
                // Read com (33*t bytes)
                val com = try {
                    VssCommitment.fromBytes(b.sliceArray(0 until 33 * t), t)
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid VSS commitment")
                }
                // Read pop (64 bytes)
                val pop = b.sliceArray(33 * t until b.size)
                return ParticipantMsg(com, pop)
            }
        }
    }

    class CoordinatorMsg(
        val comsToSecrets: List<GroupElement>,
        val sumComsToNonconstTerms: List<GroupElement>,
        val pops: List<ByteArray>
    ) {
        fun toBytes(): ByteArray {
            return (comsToSecrets + sumComsToNonconstTerms)
                .fold(byteArrayOf()) { acc, p -> acc + p.toCompressedBytesWithInfinity().value.toByteArray() } +
                    pops.fold(byteArrayOf()) { acc, pop -> acc + pop }
        }

        companion object {
            fun lenBytes(t: Int, n: Int): Int = 97 * n + 33 * (t - 1)

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, t: Int, n: Int): CoordinatorMsg {
                if (b.size != lenBytes(t, n)) {
                    throw IllegalArgumentException()
                }
                // Read coms_to_secrets (33*n bytes)
                val comsToSecrets = try {
                    (0 until n).map { i ->
                        GroupElement.fromCompressedBytesWithInfinity(PublicKey(b.sliceArray(33 * i until 33 * i + 33)))
                    }
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid commitment to secret")
                }
                val rest = b.sliceArray(33 * n until b.size)

                // Read sum_coms_to_nonconst_terms (33*(t-1) bytes)
                val sumComsToNonconstTerms = try {
                    (0 until t - 1).map { j ->
                        GroupElement.fromCompressedBytesWithInfinity(PublicKey(rest.sliceArray(33 * j until 33 * j + 33)))
                    }
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid sum commitment to non-constant term")
                }
                val rest2 = rest.sliceArray(33 * (t - 1) until rest.size)

                // Read pops (64*n bytes)
                val pops = (0 until n).map { i -> rest2.sliceArray(64 * i until 64 * i + 64) }

                return CoordinatorMsg(comsToSecrets, sumComsToNonconstTerms, pops)
            }
        }
    }

    class CoordinatorInvestigationMsg(val partialPubshares: List<GroupElement>) {
        fun toBytes(): ByteArray {
            return partialPubshares.fold(byteArrayOf()) { acc, p -> acc + p.toCompressedBytesWithInfinity().value.toByteArray() }
        }

        companion object {
            fun lenBytes(n: Int): Int = 33 * n

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, n: Int): CoordinatorInvestigationMsg {
                if (b.size != lenBytes(n)) {
                    throw IllegalArgumentException()
                }
                val partialPubshares = try {
                    (0 until n).map { i ->
                        GroupElement.fromCompressedBytesWithInfinity(PublicKey(b.sliceArray(33 * i until 33 * i + 33)))
                    }
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid partial pubshare")
                }
                return CoordinatorInvestigationMsg(partialPubshares)
            }
        }
    }

    ///
    /// Other common definitions
    ///

    fun assembleSumComs(comsToSecrets: List<GroupElement>, sumComsToNonconstTerms: List<GroupElement>): VssCommitment {
        // Sum the commitments to the secrets
        return VssCommitment(listOf(comsToSecrets.geSum()) + sumComsToNonconstTerms)
    }

    ///
    /// Participant
    ///

    class ParticipantState(
        val t: Int,
        val n: Int,
        val participantId: Int,
        val comToSecret: GroupElement
    )

    class ParticipantInvestigationData(
        val n: Int,
        val participantId: Int,
        val secshare: Scalar,
        val pubshare: GroupElement
    )

    // To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive
    // computations, we omit explicit invocations of an interactive equality check
    // protocol. ChillDKG will take care of invoking the equality check protocol.

    /**
     * @return the participant state, the message to send to the coordinator, and
     * the list of n partial secret shares generated by this participant. The item
     * at index i is supposed to be made available to participant i privately,
     * e.g., via an external secure channel. See also [participantStep2PrepareSecshare].
     */
    fun participantStep1(
        seed: ByteArray,
        t: Int,
        n: Int,
        participantId: Int,
        auxRand: ByteArray
    ): Triple<ParticipantState, ByteArray, List<Scalar>> {
        if (t > n) {
            throw IllegalArgumentException()
        }
        if (participantId >= n) {
            throw IndexOutOfBoundsException()
        }
        if (seed.size != 32) {
            throw IllegalArgumentException()
        }
        if (auxRand.size != 32) {
            throw IllegalArgumentException()
        }

        val vss = Vss.generate(seed, t)
        val partialSecsharesFromMe = vss.secshares(n)
        val pop = popProve(vss.secret().toByteArray(), participantId, auxRand)

        val com = vss.commit()
        val comToSecret = com.commitmentToSecret()
        val msg = ParticipantMsg(com, pop).toBytes()
        val state = ParticipantState(t, n, participantId, comToSecret)
        return Triple(state, msg, partialSecsharesFromMe)
    }

    /**
     * Helper function to prepare the secshare for participant id's
     * [participantStep2] by summing the partial secshares returned by all
     * participants' [participantStep1].
     *
     * In a pure run of SimplPedPop where secret shares are sent via external
     * secure channels (i.e., EncPedPop is not used), each participant needs to
     * run this function in preparation of their [participantStep2]. Since this
     * computation involves secret data, it cannot be delegated to the
     * coordinator as opposed to other aggregation steps.
     *
     * If EncPedPop is used instead (as a wrapper of SimplPedPop), the
     * coordinator can securely aggregate the encrypted partial secshares into an
     * encrypted secshare by exploiting the additively homomorphic property of
     * the encryption.
     */
    fun participantStep2PrepareSecshare(partialSecshares: List<Scalar>): Scalar {
        return partialSecshares.scalarSum()
    }

    /**
     * @throws FaultyCoordinatorError if the coordinator is faulty.
     * @throws FaultyParticipantOrCoordinatorError if another known participant or the coordinator is faulty.
     * @throws UnknownFaultyParticipantOrCoordinatorError if another unknown participant or the coordinator is faulty.
     */
    fun participantStep2(
        state: ParticipantState,
        cmsg: ByteArray,
        secshare: Scalar
    ): Pair<DkgOutput, ByteArray> {
        val t = state.t
        val n = state.n
        val participantId = state.participantId
        val cmsgParsed = try {
            CoordinatorMsg.fromBytes(cmsg, t = t, n = n)
        } catch (e: MsgParseError) {
            throw FaultyCoordinatorError(e.message)
        }
        val comsToSecrets = cmsgParsed.comsToSecrets
        val sumComsToNonconstTerms = cmsgParsed.sumComsToNonconstTerms
        val pops = cmsgParsed.pops

        if (comsToSecrets[participantId] != state.comToSecret) {
            throw FaultyCoordinatorError(
                "Coordinator sent unexpected first group element for local participant id"
            )
        }

        for (i in 0 until n) {
            if (i == participantId) {
                // No need to check our own pop.
                continue
            }
            if (comsToSecrets[i].isInfinity) {
                throw FaultyParticipantOrCoordinatorError(
                    i, "Participant sent invalid commitment"
                )
            }
            // This can be optimized: We serialize the comsToSecrets[i] here, but
            // schnorrVerify (inside popVerify) will need to deserialize it again,
            // which involves computing a square root to obtain the y coordinate.
            if (!popVerify(pops[i], comsToSecrets[i].getX().toByteArray(), i)) {
                throw FaultyParticipantOrCoordinatorError(
                    i, "Participant sent invalid proof-of-knowledge"
                )
            }
        }

        val sumComs = assembleSumComs(comsToSecrets, sumComsToNonconstTerms)
        // Verifying the tweaked secshare against the tweaked pubshare is equivalent
        // to verifying the untweaked secshare against the untweaked pubshare, but
        // avoids computing the untweaked pubshare in the happy path and thereby
        // moves a group addition to the error path.
        val (sumComsTweaked, tweak, pubtweak) = sumComs.invalidTaprootCommit()
        val pubshareTweaked = sumComsTweaked.pubshare(participantId)
        val secshareTweaked = secshare.plus(tweak)
        if (!VssCommitment.verifySecshare(secshareTweaked, pubshareTweaked)) {
            val pubshare = pubshareTweaked.add(pubtweak.negate())
            throw UnknownFaultyParticipantOrCoordinatorError(
                ParticipantInvestigationData(n, participantId, secshare, pubshare),
                "Received invalid secshare; consider using " +
                        "participant_investigate() to determine a faulty party"
            )
        }

        val threshPk = sumComsTweaked.commitmentToSecret()
        val pubshares = (0 until n).map { i ->
            if (i != participantId) sumComsTweaked.pubshare(i) else pubshareTweaked
        }
        val dkgOutput = DkgOutput(
            secshareTweaked.toByteArray(),
            threshPk.toCompressedBytes().value.toByteArray(),
            pubshares.map { it.toCompressedBytes().value.toByteArray() }
        )
        val eqInput = t.to4LengthByteArray() + sumComs.toBytes()
        return Pair(dkgOutput, eqInput)
    }

    /**
     * This function does not return normally. Instead, it raises one of
     * [FaultyParticipantOrCoordinatorError] or [FaultyCoordinatorError].
     */
    fun participantInvestigate(
        error: UnknownFaultyParticipantOrCoordinatorError,
        cinv: ByteArray,
        partialSecshares: List<Scalar>
    ): Nothing {
        val invData = error.invData as ParticipantInvestigationData
        val n = invData.n
        val participantId = invData.participantId
        val secshare = invData.secshare
        val pubshare = invData.pubshare
        if (partialSecshares.size != n) {
            throw IllegalArgumentException()
        }

        val cinvParsed = try {
            CoordinatorInvestigationMsg.fromBytes(cinv, n = n)
        } catch (e: MsgParseError) {
            throw FaultyCoordinatorError(e.message)
        }
        val partialPubshares = cinvParsed.partialPubshares

        if (partialPubshares.geSum() != pubshare) {
            throw FaultyCoordinatorError("Sum of partial pubshares not equal to pubshare")
        }

        if (partialSecshares.scalarSum() != secshare) {
            throw SecshareSumError("Sum of partial secshares not equal to secshare")
        }

        for (i in 0 until n) {
            if (!VssCommitment.verifySecshare(partialSecshares[i], partialPubshares[i])) {
                if (i != participantId) {
                    throw FaultyParticipantOrCoordinatorError(
                        i, "Participant sent invalid partial secshare"
                    )
                } else {
                    // We are not faulty, so the coordinator must be.
                    throw FaultyCoordinatorError(
                        "Coordinator fiddled with the share from me to myself"
                    )
                }
            }
        }

        // We now know:
        //  - The sum of the partial secshares is equal to the secshare.
        //  - The sum of the partial pubshares is equal to the pubshare.
        //  - Every partial secshare matches its corresponding partial pubshare.
        // Hence, the secshare matches the pubshare.
        check(VssCommitment.verifySecshare(secshare, pubshare))

        // This should never happen (unless the caller fiddled with the inputs).
        throw IllegalStateException(
            "participant_investigate() was called, but all inputs are consistent."
        )
    }

    ///
    /// Coordinator
    ///

    /**
     * @return the coordinator message, the DKG output (without a secret share),
     * and the input for the equality check protocol.
     * @throws FaultyParticipantError if a participant is faulty.
     */
    fun coordinatorStep(
        pmsgs: List<ByteArray>,
        t: Int,
        n: Int
    ): Triple<ByteArray, DkgOutput, ByteArray> {
        if (pmsgs.size != n) {
            throw IllegalArgumentException()
        }
        val pmsgsParsed = pmsgs.mapIndexed { i, pmsg ->
            try {
                ParticipantMsg.fromBytes(pmsg, t = t)
            } catch (e: MsgParseError) {
                throw FaultyParticipantError(i, e.message)
            }
        }
        // Sum the commitments to the i-th coefficients for i > 0
        //
        // This procedure corresponds to the one described by Pedersen in Section 5.1
        // of "Non-Interactive and Information-Theoretic Secure Verifiable Secret
        // Sharing". However, we don't sum the commitments to the secrets (i == 0)
        // because they'll be necessary to check the pops.
        val comsToSecrets = pmsgsParsed.map { it.com.commitmentToSecret() }
        // But we can sum the commitments to the non-constant terms.
        val sumComsToNonconstTerms = (0 until t - 1).map { j ->
            pmsgsParsed.map { it.com.commitmentToNonconstTerms()[j] }.geSum()
        }
        val pops = pmsgsParsed.map { it.pop }
        val cmsg = CoordinatorMsg(comsToSecrets, sumComsToNonconstTerms, pops).toBytes()

        val sumComs = assembleSumComs(comsToSecrets, sumComsToNonconstTerms)
        val (sumComsTweaked, _, _) = sumComs.invalidTaprootCommit()
        val threshPk = sumComsTweaked.commitmentToSecret()
        val pubshares = (0 until n).map { sumComsTweaked.pubshare(it) }

        val dkgOutput = DkgOutput(
            null,
            threshPk.toCompressedBytes().value.toByteArray(),
            pubshares.map { it.toCompressedBytes().value.toByteArray() }
        )
        val eqInput = t.to4LengthByteArray() + sumComs.toBytes()
        return Triple(cmsg, dkgOutput, eqInput)
    }

    fun coordinatorInvestigate(pmsgs: List<ByteArray>, t: Int): List<ByteArray> {
        val n = pmsgs.size
        val pmsgsParsed = pmsgs.map { ParticipantMsg.fromBytes(it, t = t) }
        val allPartialPubshares = (0 until n).map { i ->
            pmsgsParsed.map { it.com.pubshare(i) }
        }
        return (0 until n).map { i ->
            CoordinatorInvestigationMsg(allPartialPubshares[i]).toBytes()
        }
    }
}
