package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import ac.cord.auxiliary.cryptography.toBigInteger
import fr.acinq.bitcoin.PublicKey

/**
 * Reference port of ChillDKG (chilldkg_ref/chilldkg.py).
 *
 * WARNING: This code is slow and not hardened against side channel attacks. Do
 * not use for anything but tests.
 *
 * In addition to the exceptions documented for each function, all public API
 * functions may throw [IllegalArgumentException] when called with arguments of
 * unexpected structure (e.g., wrong length). These structural errors (ValueError
 * in the Python reference) are not documented per function.
 */
object ChillDkg {

    ///
    /// Equality check protocol CertEq
    ///

    private fun certeqMessage(x: ByteArray, participantId: Int): ByteArray {
        // Domain separation as described in BIP 340
        var prefix = (BIP_TAG + "certeq message").encodeToByteArray()
        prefix = prefix + ByteArray(33 - prefix.size)
        check(prefix.size == 33)
        return prefix + participantId.to4LengthByteArray() + x
    }

    private fun certeqParticipantStep(hostseckey: ByteArray, participantId: Int, x: ByteArray, auxRand: ByteArray): ByteArray {
        val msg = certeqMessage(x, participantId)
        return ChillDkgCrypto.schnorrSign(msg, hostseckey, auxRand)
    }

    private fun certeqCertLen(n: Int): Int = 64 * n

    private fun certeqVerify(hostpubkeys: List<ByteArray>, x: ByteArray, cert: ByteArray) {
        val n = hostpubkeys.size
        if (cert.size != certeqCertLen(n)) {
            throw IllegalArgumentException()
        }
        for (i in 0 until n) {
            val msg = certeqMessage(x, i)
            val valid = ChillDkgCrypto.schnorrVerify(
                msg,
                // Dropping the sign byte from hostpubkeys[i] is okay because msg
                // commits on the full hostpubkeys[i]: it encodes all hostpubkeys
                // together with the id i.
                hostpubkeys[i].sliceArray(1 until 33),
                cert.sliceArray(i * 64 until (i + 1) * 64)
            )
            if (!valid) {
                throw InvalidSignatureInCertificateError(i)
            }
        }
    }

    private fun certeqCoordinatorStep(sigs: List<ByteArray>): ByteArray {
        return sigs.fold(byteArrayOf()) { acc, sig -> acc + sig }
    }

    private class InvalidSignatureInCertificateError(val participantId: Int) : IllegalArgumentException()

    ///
    /// Recovery acknowledgment helpers
    ///

    private fun recoveryAckMessage(x: ByteArray, participantId: Int): ByteArray {
        // Domain separation as described in BIP 340
        var prefix = (BIP_TAG + "recovery acknowledgment").encodeToByteArray()
        prefix = prefix + ByteArray(33 - prefix.size)
        check(prefix.size == 33)
        return prefix + participantId.to4LengthByteArray() + x
    }

    private fun recoveryAckSign(hostseckey: ByteArray, participantId: Int, x: ByteArray, auxRand: ByteArray): ByteArray {
        val msg = recoveryAckMessage(x, participantId)
        return ChillDkgCrypto.schnorrSign(msg, hostseckey, auxRand)
    }

    ///
    /// Host keys
    ///

    /**
     * Compute the participant's host public key from the host secret key.
     *
     * The host public key is the long-term cryptographic identity of the
     * participant.
     *
     * This function interprets [hostseckey] as big-endian integer, and computes
     * the corresponding "plain" public key in compressed serialization (33
     * bytes, starting with 0x02 or 0x03). This is the key generation procedure
     * traditionally used in Bitcoin, e.g., for ECDSA. In other words, this
     * function is equivalent to `IndividualPubkey` as defined in BIP 327.
     *
     * The same host secret key (and thus the same host public key) can be used
     * in multiple DKG sessions.
     *
     * @param hostseckey this participant's long-term secret key (32 bytes). The
     * key **must** be 32 bytes of cryptographically secure randomness with
     * sufficient entropy to be unpredictable. All outputs of a successful
     * participant in a session can be recovered from (a backup of) the key and
     * per-session recovery data.
     * @return the host public key (33 bytes).
     * @throws HostSeckeyError if the host secret key is invalid.
     */
    fun hostpubkeyGen(hostseckey: ByteArray): ByteArray {
        if (hostseckey.size != 32) {
            throw IllegalArgumentException()
        }
        return try {
            ChillDkgCrypto.pubkeyGenPlain(hostseckey)
        } catch (e: IllegalArgumentException) {
            throw HostSeckeyError()
        }
    }

    /**
     * Raised if the host secret key is invalid.
     */
    class HostSeckeyError(message: String? = null) : IllegalArgumentException(message)

    ///
    /// Session input and outputs
    ///

    /**
     * A [SessionParams] holds the common parameters of a DKG session.
     *
     * [hostpubkeys]: ordered list of the host public keys of all participants.
     * [t]: the participation threshold `t`. This is the number of participants
     * that will be required to sign. It must hold that
     * `1 <= t <= hostpubkeys.size <= 2**32 - 1`.
     *
     * Each participant **must** ensure to have authentic copies of all other
     * participants' host public keys before the start of the session, e.g., by
     * confirming authenticity of each host public key with the expected key
     * holder out of band.
     *
     * A DKG session will fail if the participants and the coordinator in a
     * session don't have the [hostpubkeys] in the same order. If there is no
     * canonical order of the participants in the application, the caller can
     * sort the list of host public keys with the KeySort algorithm specified in
     * BIP 327 to abstract away from the order.
     */
    class SessionParams(
        val hostpubkeys: List<ByteArray>,
        val t: Int
    )

    private fun paramsValidate(params: SessionParams) {
        val hostpubkeys = params.hostpubkeys
        val t = params.t

        if (!(1 <= t && t <= hostpubkeys.size && hostpubkeys.size.toLong() <= 0xFFFFFFFFL)) {
            throw ThresholdOrCountError()
        }

        // Check that all hostpubkeys are valid
        for ((i, hostpubkey) in hostpubkeys.withIndex()) {
            try {
                GroupElement.fromCompressedBytes(PublicKey(hostpubkey))
            } catch (e: Exception) {
                throw InvalidHostPubkeyError(i)
            }
        }

        // Check for duplicate hostpubkeys and find the corresponding ids
        val seen = mutableListOf<ByteArray>()
        for ((i, hostpubkey) in hostpubkeys.withIndex()) {
            val firstIndex = seen.indexOfFirst { it.contentEquals(hostpubkey) }
            if (firstIndex >= 0) {
                throw DuplicateHostPubkeyError(firstIndex, i)
            }
            seen.add(hostpubkey)
        }
    }

    /**
     * Return a hash of the session parameters for out-of-band comparison.
     *
     * In the common scenario that the participants obtain host public keys from
     * the other participants over channels that do not provide end-to-end
     * authentication of the sending participant (e.g., if the participants
     * simply send their unauthenticated host public keys to the coordinator, who
     * is supposed to relay them to all participants), the parameters hash serves
     * as a convenient way to perform an out-of-band comparison of all host
     * public keys. It is a collision-resistant cryptographic hash of the
     * [SessionParams]. As a result, if all participants have obtained an
     * identical parameters hash (as can be verified out-of-band), then they all
     * agree on all host public keys and the threshold `t`, and in particular,
     * all participants have obtained authentic public host keys.
     *
     * @return the parameters hash, a 32-byte string.
     * @throws InvalidHostPubkeyError if `hostpubkeys` contains an invalid public key.
     * @throws DuplicateHostPubkeyError if `hostpubkeys` contains duplicates.
     * @throws ThresholdOrCountError if `1 <= t <= hostpubkeys.size <= 2**32 - 1` does not hold.
     */
    fun paramsHash(params: SessionParams): ByteArray {
        paramsValidate(params)
        val paramsHash = taggedHashBipDkg(
            "params_hash",
            params.t.to4LengthByteArray() + params.hostpubkeys.fold(byteArrayOf()) { acc, hp -> acc + hp }
        )
        check(paramsHash.size == 32)
        return paramsHash
    }

    /**
     * Base exception for invalid [SessionParams].
     */
    open class SessionParamsError(message: String? = null) : IllegalArgumentException(message)

    /**
     * Raised if two participants have identical host public keys.
     *
     * Assuming the host public keys in question have been transmitted correctly,
     * this exception implies that at least one of the two participants is faulty
     * (because duplicates occur only with negligible probability if keys are
     * generated honestly).
     */
    class DuplicateHostPubkeyError(
        val participantId1: Int,
        val participantId2: Int
    ) : SessionParamsError()

    /**
     * Raised if a host public key is invalid.
     *
     * This exception is raised when a host public key in the [SessionParams] is
     * not a valid public key in compressed serialization. Assuming the host
     * public key in question has been transmitted correctly, this exception
     * implies that the corresponding participant is faulty.
     */
    class InvalidHostPubkeyError(
        val participantId: Int
    ) : SessionParamsError()

    /**
     * Raised if `1 <= t <= hostpubkeys.size <= 2**32 - 1` does not hold.
     */
    class ThresholdOrCountError : SessionParamsError()

    ///
    /// Messages
    ///

    class ParticipantMsg1(val encPmsg: EncPedPop.ParticipantMsg) {
        fun toBytes(): ByteArray = encPmsg.toBytes()

        companion object {
            fun lenBytes(t: Int, n: Int): Int = EncPedPop.ParticipantMsg.lenBytes(t, n)

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, t: Int, n: Int): ParticipantMsg1 {
                if (b.size != lenBytes(t, n)) {
                    throw IllegalArgumentException()
                }
                val encPmsg = EncPedPop.ParticipantMsg.fromBytes(b, t = t, n = n) // MsgParseError if invalid
                return ParticipantMsg1(encPmsg)
            }
        }
    }

    class ParticipantMsg2(val sig: ByteArray) {
        fun toBytes(): ByteArray = sig

        companion object {
            fun lenBytes(): Int = 64

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             */
            fun fromBytes(b: ByteArray): ParticipantMsg2 {
                if (b.size != lenBytes()) {
                    throw IllegalArgumentException()
                }
                return ParticipantMsg2(b)
            }
        }
    }

    class CoordinatorMsg1(
        val encCmsg: EncPedPop.CoordinatorMsg,
        val encSecshares: List<Scalar>
    ) {
        fun toBytes(): ByteArray {
            return encCmsg.toBytes() + encSecshares.fold(byteArrayOf()) { acc, share -> acc + share.toByteArray() }
        }

        companion object {
            fun lenBytes(t: Int, n: Int): Int = EncPedPop.CoordinatorMsg.lenBytes(t, n) + 32 * n

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, t: Int, n: Int): CoordinatorMsg1 {
                if (b.size != lenBytes(t, n)) {
                    throw IllegalArgumentException()
                }

                // Read enc_cmsg (MsgParseError if invalid)
                val encCmsgLen = EncPedPop.CoordinatorMsg.lenBytes(t, n)
                val encCmsg = EncPedPop.CoordinatorMsg.fromBytes(b.sliceArray(0 until encCmsgLen), t = t, n = n)
                val rest = b.sliceArray(encCmsgLen until b.size)

                // Read enc_secshares (32*n bytes)
                val encSecshares = try {
                    (0 until n).map { i ->
                        Scalar.fromBytesChecked(rest.sliceArray(32 * i until 32 * i + 32))
                    }
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid encrypted secret shares")
                }

                return CoordinatorMsg1(encCmsg, encSecshares)
            }
        }
    }

    class CoordinatorMsg2(val cert: ByteArray) {
        fun toBytes(): ByteArray = cert

        companion object {
            fun lenBytes(n: Int): Int = 64 * n

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             */
            fun fromBytes(b: ByteArray, n: Int): CoordinatorMsg2 {
                if (b.size != lenBytes(n)) {
                    throw IllegalArgumentException()
                }
                return CoordinatorMsg2(b)
            }
        }
    }

    class CoordinatorInvestigationMsg(val encCinv: EncPedPop.CoordinatorInvestigationMsg) {
        fun toBytes(): ByteArray = encCinv.toBytes()

        companion object {
            fun lenBytes(n: Int): Int = EncPedPop.CoordinatorInvestigationMsg.lenBytes(n)

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, n: Int): CoordinatorInvestigationMsg {
                if (b.size != lenBytes(n)) {
                    throw IllegalArgumentException()
                }
                val encCinv = EncPedPop.CoordinatorInvestigationMsg.fromBytes(b, n = n) // MsgParseError if invalid
                return CoordinatorInvestigationMsg(encCinv)
            }
        }
    }

    class RecoveryAckMsg(val sig: ByteArray) {
        fun toBytes(): ByteArray = sig

        companion object {
            fun lenBytes(): Int = 64

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             */
            fun fromBytes(b: ByteArray): RecoveryAckMsg {
                if (b.size != lenBytes()) {
                    throw IllegalArgumentException()
                }
                return RecoveryAckMsg(b)
            }
        }
    }

    private class DeserializedRecoveryData(
        val t: Int,
        val sumComs: VssCommitment,
        val hostpubkeys: List<ByteArray>,
        val pubnonces: List<ByteArray>,
        val encSecshares: List<Scalar>,
        val cert: ByteArray
    )

    /**
     * @throws IllegalArgumentException if the recovery data is malformed.
     */
    private fun deserializeRecoveryData(b: ByteArray): DeserializedRecoveryData {
        var rest = b

        // Read t (4 bytes)
        if (rest.size < 4) {
            throw IllegalArgumentException()
        }
        val t = rest.sliceArray(0 until 4).toBigInteger().intValue()
        rest = rest.sliceArray(4 until rest.size)

        // Read sum_coms (33*t bytes)
        if (rest.size < 33 * t) {
            throw IllegalArgumentException()
        }
        val sumComs = VssCommitment.fromBytes(rest.sliceArray(0 until 33 * t), t = t)
        rest = rest.sliceArray(33 * t until rest.size)

        // Compute n
        val n = rest.size / (33 + 33 + 32 + 64)
        val remainder = rest.size % (33 + 33 + 32 + 64)
        if (remainder != 0) {
            throw IllegalArgumentException()
        }

        // Read hostpubkeys (33*n bytes)
        check(rest.size >= 33 * n)
        val hostpubkeys = (0 until n).map { i -> rest.sliceArray(33 * i until 33 * i + 33) }
        rest = rest.sliceArray(33 * n until rest.size)

        // Read pubnonces (33*n bytes)
        check(rest.size >= 33 * n)
        val pubnonces = (0 until n).map { i -> rest.sliceArray(33 * i until 33 * i + 33) }
        rest = rest.sliceArray(33 * n until rest.size)

        // Read enc_secshares (32*n bytes)
        check(rest.size >= 32 * n)
        val encSecshares = (0 until n).map { i ->
            Scalar.fromBytesChecked(rest.sliceArray(32 * i until 32 * i + 32))
        }
        rest = rest.sliceArray(32 * n until rest.size)

        // Read cert (64*n bytes)
        check(rest.size >= 64 * n)
        val cert = rest.sliceArray(0 until 64 * n)
        rest = rest.sliceArray(64 * n until rest.size)

        check(rest.isEmpty())
        return DeserializedRecoveryData(t, sumComs, hostpubkeys, pubnonces, encSecshares, cert)
    }

    private fun hostpubkeysIndexOf(hostpubkeys: List<ByteArray>, hostpubkey: ByteArray): Int {
        return hostpubkeys.indexOfFirst { it.contentEquals(hostpubkey) }
    }

    private fun hostpubkeysEqual(a: List<ByteArray>, b: List<ByteArray>): Boolean {
        return a.size == b.size && a.indices.all { a[it].contentEquals(b[it]) }
    }

    ///
    /// Participant
    ///

    class ParticipantState1(
        val params: SessionParams,
        val participantId: Int,
        val encState: EncPedPop.ParticipantState
    )

    class ParticipantState2(
        val params: SessionParams,
        val eqInput: ByteArray,
        val dkgOutput: DkgOutput
    )

    /**
     * Perform a participant's first step of a ChillDKG session.
     *
     * @param hostseckey participant's long-term host secret key (32 bytes).
     * @param params common session parameters.
     * @param random FRESH random byte string (32 bytes).
     * @return the participant's session state after this step (to be passed as
     * an argument to [participantStep2]; the state **must not** be reused) and
     * the first message to be sent to the coordinator (`33*t + 32*n + 97` bytes).
     * @throws HostSeckeyError if the host secret key is invalid, or if the key
     * does not match any entry of `hostpubkeys`.
     * @throws InvalidHostPubkeyError if `hostpubkeys` contains an invalid public key.
     * @throws DuplicateHostPubkeyError if `hostpubkeys` contains duplicates.
     * @throws ThresholdOrCountError if `1 <= t <= hostpubkeys.size <= 2**32 - 1` does not hold.
     * @throws RandomnessError if [random] is all zeroes. This check guards
     * against the case of a malfunctioning random number generator.
     */
    fun participantStep1(
        hostseckey: ByteArray,
        params: SessionParams,
        random: ByteArray
    ): Pair<ParticipantState1, ByteArray> {
        val hostpubkey = hostpubkeyGen(hostseckey) // IllegalArgumentException if hostseckey.size != 32

        paramsValidate(params)
        val hostpubkeys = params.hostpubkeys
        val t = params.t

        val participantId = hostpubkeysIndexOf(hostpubkeys, hostpubkey)
        if (participantId < 0) {
            throw HostSeckeyError("Host secret key does not match any host public key")
        }
        if (random.size != 32) {
            throw IllegalArgumentException()
        }
        if (random.all { it == 0.toByte() }) {
            throw RandomnessError()
        }

        val (encState, encPmsg) = EncPedPop.participantStep1(
            // We know that EncPedPop uses its seed only by feeding it to a hash
            // function. Thus, it is sufficient that the seed has a high entropy,
            // and so we can simply pass the hostseckey as seed.
            seed = hostseckey,
            deckey = hostseckey,
            t = t,
            // This requires the joint security of Schnorr signatures and ECDH.
            enckeys = hostpubkeys,
            participantId = participantId,
            random = random
        )

        val state1 = ParticipantState1(params, participantId, encState)
        return Pair(state1, encPmsg)
    }

    /**
     * Raised if the randomness is all zeroes.
     */
    class RandomnessError : IllegalArgumentException()

    /**
     * Perform a participant's second step of a ChillDKG session.
     *
     * **Warning:** After sending the returned message to the coordinator, the
     * caller **must not** erase the hostseckey, even if the coordinator reply
     * needed for the [participantFinalize] call is not received. The underlying
     * reason is that some other participant may receive the coordinator reply,
     * deem the DKG session successful and use the resulting threshold public key
     * (e.g., by sending funds to it). If the coordinator reply remains missing,
     * that other participant can, at any point in the future, convince this
     * participant of the success of the DKG session by presenting recovery data,
     * from which this participant can recover the DKG output using the
     * [participantRecover] function.
     *
     * @param hostseckey participant's long-term host secret key (32 bytes).
     * @param state1 the participant's session state as output by [participantStep1].
     * @param cmsg1 the first message received from the coordinator (`162*n + 33*(t-1)` bytes).
     * @param auxRand auxiliary randomness (32 bytes). FRESH 32-byte randomness
     * is optimal, but 16 random bytes or a counter padded to 32 bytes is
     * acceptable (see BIP 340).
     * @return the participant's session state after this step (to be passed as
     * an argument to [participantFinalize]; the state **must not** be reused)
     * and the second message to be sent to the coordinator (64 bytes).
     * @throws HostSeckeyError if the host secret key is invalid or if it does
     * not match the one used in [participantStep1].
     * @throws FaultyCoordinatorError if the coordinator is faulty.
     * @throws FaultyParticipantOrCoordinatorError if another known participant or the coordinator is faulty.
     * @throws UnknownFaultyParticipantOrCoordinatorError if another unknown
     * participant or the coordinator is faulty, but running the optional
     * investigation procedure of the protocol is necessary to determine a
     * suspected participant.
     */
    fun participantStep2(
        hostseckey: ByteArray,
        state1: ParticipantState1,
        cmsg1: ByteArray,
        auxRand: ByteArray
    ): Pair<ParticipantState2, ByteArray> {
        val hostpubkey = hostpubkeyGen(hostseckey) // HostSeckeyError if invalid or IllegalArgumentException if hostseckey.size != 32
        if (auxRand.size != 32) {
            throw IllegalArgumentException()
        }

        val params = state1.params
        val participantId = state1.participantId
        val encState = state1.encState
        if (!hostpubkey.contentEquals(params.hostpubkeys[participantId])) {
            throw HostSeckeyError(
                "Host secret key does not match the one used in participant_step1"
            )
        }
        val t = encState.simplState.t
        val cmsg1Parsed = try {
            CoordinatorMsg1.fromBytes(cmsg1, t = t, n = params.hostpubkeys.size)
        } catch (e: MsgParseError) {
            throw FaultyCoordinatorError(e.message)
        }
        val encCmsg = cmsg1Parsed.encCmsg
        val encSecshares = cmsg1Parsed.encSecshares

        val (encDkgOutput, eqInput) = EncPedPop.participantStep2(
            state = encState,
            deckey = hostseckey,
            cmsg = encCmsg.toBytes(),
            encSecshare = encSecshares[participantId]
        )

        // Include the enc_shares in eq_input to ensure that participants agree on
        // all shares, which in turn ensures that they have the right recovery data.
        val eqInputFull = eqInput + encSecshares.fold(byteArrayOf()) { acc, share -> acc + share.toByteArray() }
        val state2 = ParticipantState2(params, eqInputFull, encDkgOutput)
        val sig = certeqParticipantStep(hostseckey, participantId, eqInputFull, auxRand)
        val pmsg2 = ParticipantMsg2(sig).toBytes()
        return Pair(state2, pmsg2)
    }

    /**
     * Perform a participant's final step of a ChillDKG session.
     *
     * If this function returns properly (without an exception), then this
     * participant deems the DKG session successful. It is, however, possible
     * that other participants have received a `cmsg2` from the coordinator that
     * made them raise an exception instead, or that they have not received a
     * `cmsg2` from the coordinator at all. These participants can, at any point
     * in time in the future (e.g., when initiating a signing session), be
     * convinced to deem the session successful by presenting the recovery data
     * to them, from which they can recover the DKG outputs using the
     * [participantRecover] function.
     *
     * To protect against data loss scenarios, callers **should** ensure that
     * all participants deem the DKG session successful (which also implies that
     * they have a redundant copy of the recovery data) before using the
     * threshold public key (e.g., before sending funds to it). The recommended
     * way of doing so is by collecting acknowledgment signatures via
     * [participantRecoveryAckSign].
     *
     * **Warning:** Even when obtaining an exception, the caller **must not**
     * conclude that the DKG session has failed, and as a consequence, the caller
     * **must not** erase the hostseckey.
     *
     * @param state2 the participant's state as output by [participantStep2].
     * @param cmsg2 the second message received from the coordinator (`64*n` bytes).
     * @return the DKG output and the serialized recovery data.
     * @throws FaultyCoordinatorError if the coordinator is faulty.
     */
    fun participantFinalize(
        state2: ParticipantState2,
        cmsg2: ByteArray
    ): Pair<DkgOutput, ByteArray> {
        val params = state2.params
        val eqInput = state2.eqInput
        val dkgOutput = state2.dkgOutput
        val cmsg2Parsed = CoordinatorMsg2.fromBytes(cmsg2, n = params.hostpubkeys.size)
        try {
            certeqVerify(params.hostpubkeys, eqInput, cmsg2Parsed.cert)
        } catch (e: InvalidSignatureInCertificateError) {
            throw FaultyCoordinatorError(
                "Coordinator has provided a certificate with an invalid signature"
            )
        }
        return Pair(dkgOutput, eqInput + cmsg2Parsed.cert)
    }

    /**
     * Investigate who is to blame for a failed ChillDKG session.
     *
     * This function can optionally be called when [participantStep2] throws
     * [UnknownFaultyParticipantOrCoordinatorError]. It narrows down the
     * suspected faulty parties by analyzing the investigation message provided
     * by the coordinator.
     *
     * This function does not return normally. Instead, it raises one of two
     * exceptions.
     *
     * @param error [UnknownFaultyParticipantOrCoordinatorError] raised by [participantStep2].
     * @param cinv coordinator investigation message for this participant as
     * output by [coordinatorInvestigate] (`65*n` bytes).
     * @throws FaultyParticipantOrCoordinatorError if another known participant or the coordinator is faulty.
     * @throws FaultyCoordinatorError if the coordinator is faulty.
     */
    fun participantInvestigate(
        error: UnknownFaultyParticipantOrCoordinatorError,
        cinv: ByteArray
    ): Nothing {
        val invData = error.invData as EncPedPop.ParticipantInvestigationData
        val n = invData.simplBstate.n
        val cinvParsed = try {
            CoordinatorInvestigationMsg.fromBytes(cinv, n = n)
        } catch (e: MsgParseError) {
            throw FaultyCoordinatorError(e.message)
        }
        EncPedPop.participantInvestigate(
            error = error,
            cinv = cinvParsed.encCinv.toBytes()
        )
    }

    ///
    /// Coordinator
    ///

    class CoordinatorState(
        val params: SessionParams,
        val eqInput: ByteArray,
        val dkgOutput: DkgOutput
    )

    /**
     * Perform the coordinator's first step of a ChillDKG session.
     *
     * @param pmsgs1 list of first messages received from the participants
     * (`33*t + 32*n + 97` bytes each). The list's size must equal the total
     * number of participants.
     * @param params common session parameters.
     * @return the coordinator's session state after this step (to be passed as
     * an argument to [coordinatorFinalize]; the state is not supposed to be
     * reused) and the first message to be sent to all participants
     * (`162*n + 33*(t-1)` bytes).
     * @throws InvalidHostPubkeyError if `hostpubkeys` contains an invalid public key.
     * @throws DuplicateHostPubkeyError if `hostpubkeys` contains duplicates.
     * @throws ThresholdOrCountError if `1 <= t <= hostpubkeys.size <= 2**32 - 1` does not hold.
     * @throws FaultyParticipantError if a participant is faulty.
     */
    fun coordinatorStep1(
        pmsgs1: List<ByteArray>,
        params: SessionParams
    ): Pair<CoordinatorState, ByteArray> {
        paramsValidate(params)
        val hostpubkeys = params.hostpubkeys
        val t = params.t
        if (pmsgs1.size != hostpubkeys.size) {
            throw IllegalArgumentException()
        }

        val pmsgs1Parsed = pmsgs1.mapIndexed { participantId, pmsg1 ->
            try {
                ParticipantMsg1.fromBytes(pmsg1, t = t, n = hostpubkeys.size)
            } catch (e: MsgParseError) {
                throw FaultyParticipantError(participantId, e.message)
            }
        }

        val encResult = EncPedPop.coordinatorStep(
            pmsgs = pmsgs1Parsed.map { it.encPmsg.toBytes() },
            t = t,
            enckeys = hostpubkeys
        )
        val eqInput = encResult.eqInput +
                encResult.encSecshares.fold(byteArrayOf()) { acc, share -> acc + share.toByteArray() }
        val state = CoordinatorState(params, eqInput, encResult.dkgOutput)
        val cmsg1 = CoordinatorMsg1(encResult.cmsg, encResult.encSecshares).toBytes()
        return Pair(state, cmsg1)
    }

    /**
     * Perform the coordinator's final step of a ChillDKG session.
     *
     * If this function returns properly (without an exception), then the
     * coordinator deems the DKG session successful. The returned coordinator
     * message is supposed to be sent to all participants, who are supposed to
     * pass it as input to the [participantFinalize] function.
     *
     * If this function raises an exception, then the DKG session was not
     * successful from the perspective of the coordinator. In this case, it is,
     * in principle, possible to recover the DKG outputs of the coordinator using
     * the [coordinatorRecover] function together with the recovery data from a
     * successful participant, should one exist.
     *
     * @param state the coordinator's session state as output by [coordinatorStep1].
     * @param pmsgs2 list of second messages received from the participants
     * (64 bytes each). The list's size must equal the total number of
     * participants.
     * @return the second message to be sent to all participants (`64*n` bytes),
     * the DKG output (whose `secshare` field is null, since the coordinator does
     * not have a secret share), and the serialized recovery data.
     * @throws FaultyParticipantError if a participant is faulty.
     */
    fun coordinatorFinalize(
        state: CoordinatorState,
        pmsgs2: List<ByteArray>
    ): Triple<ByteArray, DkgOutput, ByteArray> {
        val params = state.params
        val eqInput = state.eqInput
        val dkgOutput = state.dkgOutput
        if (pmsgs2.size != params.hostpubkeys.size) {
            throw IllegalArgumentException()
        }

        val pmsgs2Parsed = pmsgs2.map { ParticipantMsg2.fromBytes(it) }
        val cert = certeqCoordinatorStep(pmsgs2Parsed.map { it.sig })
        try {
            certeqVerify(params.hostpubkeys, eqInput, cert)
        } catch (e: InvalidSignatureInCertificateError) {
            throw FaultyParticipantError(
                e.participantId,
                "Participant has provided an invalid signature for the certificate"
            )
        }
        val cmsg2 = CoordinatorMsg2(cert).toBytes()
        return Triple(cmsg2, dkgOutput, eqInput + cert)
    }

    /**
     * Generate investigation messages for a ChillDKG session.
     *
     * The investigation messages will allow the participants to investigate who
     * is to blame for a failed ChillDKG session (see [participantInvestigate]).
     *
     * Each message is intended for a single participant but can be safely
     * broadcast to all participants because the messages contain no confidential
     * information.
     *
     * @param pmsgs list of serialized first messages received from the
     * participants (`33*t + 32*n + 97` bytes each).
     * @param params common session parameters.
     * @return a list of investigation messages, each intended for a single
     * participant (`65*n` bytes each).
     * @throws FaultyParticipantError if a participant is faulty.
     */
    fun coordinatorInvestigate(pmsgs: List<ByteArray>, params: SessionParams): List<ByteArray> {
        val n = pmsgs.size
        val t = params.t
        val pmsgsParsed = pmsgs.mapIndexed { participantId, pmsg ->
            try {
                ParticipantMsg1.fromBytes(pmsg, t = t, n = n)
            } catch (e: MsgParseError) {
                throw FaultyParticipantError(participantId, e.message)
            }
        }
        return EncPedPop.coordinatorInvestigate(
            pmsgsParsed.map { it.encPmsg.toBytes() }, t
        )
    }

    ///
    /// Recovery
    ///

    private fun recover(
        hostseckey: ByteArray?,
        recoveryData: ByteArray
    ): Pair<DkgOutput, SessionParams> {
        val deserialized = try {
            deserializeRecoveryData(recoveryData)
        } catch (e: Exception) {
            throw RecoveryDataError("Failed to deserialize recovery data")
        }
        val t = deserialized.t
        val sumComs = deserialized.sumComs
        val hostpubkeys = deserialized.hostpubkeys
        val pubnonces = deserialized.pubnonces
        val encSecshares = deserialized.encSecshares
        val cert = deserialized.cert

        val n = hostpubkeys.size
        val params = SessionParams(hostpubkeys, t)
        try {
            paramsValidate(params)
        } catch (e: SessionParamsError) {
            throw RecoveryDataError("Invalid session parameters in recovery data")
        }

        // Verify cert
        val eqInput = recoveryData.sliceArray(0 until recoveryData.size - cert.size)
        try {
            certeqVerify(hostpubkeys, eqInput, cert)
        } catch (e: InvalidSignatureInCertificateError) {
            throw RecoveryDataError("Invalid certificate in recovery data")
        }

        // Compute threshold pubkey and individual pubshares
        val (sumComsTweaked, tweak, _) = sumComs.invalidTaprootCommit()
        val threshPk = sumComsTweaked.commitmentToSecret()
        val pubshares = (0 until n).map { sumComsTweaked.pubshare(it) }

        var secshareTweaked: Scalar? = null
        if (hostseckey != null) {
            val hostpubkey = hostpubkeyGen(hostseckey) // IllegalArgumentException or HostSeckeyError
            val participantId = hostpubkeysIndexOf(hostpubkeys, hostpubkey)
            if (participantId < 0) {
                throw HostSeckeyError(
                    "Host secret key does not match any host public key in the recovery data"
                )
            }

            // Decrypt share
            val encContext = EncPedPop.serializeEncContext(t, hostpubkeys)
            val secshare = EncPedPop.decryptSum(
                hostseckey,
                hostpubkeys[participantId],
                pubnonces,
                encContext,
                participantId,
                encSecshares[participantId]
            )
            secshareTweaked = secshare.plus(tweak)

            // This is just a sanity check. Our signature is valid, so we have done
            // an equivalent check already during the actual session.
            check(
                VssCommitment.verifySecshare(
                    secshareTweaked, pubshares[participantId]
                )
            )
        }

        val dkgOutput = DkgOutput(
            secshareTweaked?.toByteArray(),
            threshPk.toCompressedBytes().value.toByteArray(),
            pubshares.map { it.toCompressedBytes().value.toByteArray() }
        )
        return Pair(dkgOutput, params)
    }

    /**
     * Recover the DKG output of a participant of a ChillDKG session.
     *
     * This function serves two different purposes:
     * 1. To recover from an exception in [participantFinalize], after obtaining
     *    the recovery data from another participant or the coordinator. See
     *    [participantFinalize] for background.
     * 2. To reproduce the DKG outputs on a new device, e.g., to recover from a
     *    backup after data loss.
     *
     * @param hostseckey this participant's long-term host secret key (32 bytes).
     * @param recoveryData recovery data from a successful session.
     * @return the recovered DKG output and the common parameters of the
     * recovered session.
     * @throws HostSeckeyError if the host secret key is invalid, or if the key
     * does not match the recovery data. (This can also occur if the recovery
     * data is invalid.)
     * @throws RecoveryDataError if recovery failed due to invalid recovery data.
     */
    fun participantRecover(
        hostseckey: ByteArray,
        recoveryData: ByteArray
    ): Pair<DkgOutput, SessionParams> {
        return recover(hostseckey, recoveryData)
    }

    /**
     * Recover the DKG output of the coordinator of a ChillDKG session.
     *
     * This function serves two different purposes:
     * 1. To recover from an exception in [coordinatorFinalize], after obtaining
     *    the recovery data from a participant. See [coordinatorFinalize] for
     *    background.
     * 2. To reproduce the DKG outputs on a new device, e.g., to recover from a
     *    backup after data loss.
     *
     * @param recoveryData recovery data from a successful session.
     * @return the recovered DKG output (whose `secshare` field is null, since
     * the coordinator does not have a secret share) and the common parameters of
     * the recovered session.
     * @throws RecoveryDataError if recovery failed due to invalid recovery data.
     */
    fun coordinatorRecover(
        recoveryData: ByteArray
    ): Pair<DkgOutput, SessionParams> {
        return recover(null, recoveryData)
    }

    /**
     * Raised if the recovery data is invalid.
     */
    class RecoveryDataError(message: String? = null) : IllegalArgumentException(message)

    ///
    /// Recovery acknowledgment
    ///

    /**
     * Sign recovery data to create a recovery acknowledgment.
     *
     * This function allows a participant to create an explicit acknowledgment
     * signature on the recovery data. This can be used for an optional
     * acknowledgment round where participants acknowledge that they have
     * successfully received the complete recovery data.
     *
     * @param hostseckey participant's long-term host secret key (32 bytes).
     * @param recoveryData recovery data from a successful session.
     * @param params common session parameters.
     * @param auxRand auxiliary randomness (32 bytes). FRESH 32-byte randomness
     * is optimal, but 16 random bytes or a counter padded to 32 bytes is
     * acceptable (see BIP 340).
     * @return acknowledgment signature (64 bytes).
     * @throws HostSeckeyError if the host secret key is invalid, or if it does
     * not match any host public key.
     * @throws InvalidHostPubkeyError if `hostpubkeys` contains an invalid public key.
     * @throws DuplicateHostPubkeyError if `hostpubkeys` contains duplicates.
     * @throws ThresholdOrCountError if `1 <= t <= hostpubkeys.size <= 2**32 - 1` does not hold.
     * @throws RecoveryDataError if the recovery data is invalid or does not
     * match the provided parameters.
     */
    fun participantRecoveryAckSign(
        hostseckey: ByteArray,
        recoveryData: ByteArray,
        params: SessionParams,
        auxRand: ByteArray
    ): ByteArray {
        val hostpubkey = hostpubkeyGen(hostseckey) // IllegalArgumentException if hostseckey.size != 32

        paramsValidate(params)
        val hostpubkeys = params.hostpubkeys
        val t = params.t

        val participantId = hostpubkeysIndexOf(hostpubkeys, hostpubkey)
        if (participantId < 0) {
            throw HostSeckeyError("Host secret key does not match any host public key")
        }
        if (auxRand.size != 32) {
            throw IllegalArgumentException()
        }

        val deserialized = try {
            deserializeRecoveryData(recoveryData)
        } catch (e: Exception) {
            throw RecoveryDataError("Failed to deserialize recovery data")
        }

        if (deserialized.t != t || !hostpubkeysEqual(deserialized.hostpubkeys, hostpubkeys)) {
            throw RecoveryDataError(
                "Recovery data does not match the provided session parameters"
            )
        }

        val sig = recoveryAckSign(hostseckey, participantId, recoveryData, auxRand)
        return RecoveryAckMsg(sig).toBytes()
    }

    /**
     * Verify recovery acknowledgment signatures from all participants.
     *
     * This function is used to ensure that all participants have received the
     * recovery data before the threshold public key is used (e.g., before funds
     * are sent to it).
     *
     * @param recoveryData recovery data from a successful session.
     * @param params common session parameters.
     * @param ackSigs list of acknowledgment signatures (64 bytes each) from all
     * participants, in the same order as `hostpubkeys`.
     * @throws InvalidHostPubkeyError if `hostpubkeys` contains an invalid public key.
     * @throws DuplicateHostPubkeyError if `hostpubkeys` contains duplicates.
     * @throws ThresholdOrCountError if `1 <= t <= hostpubkeys.size <= 2**32 - 1` does not hold.
     * @throws RecoveryDataError if the recovery data is invalid or does not
     * match the provided parameters.
     * @throws InvalidRecoveryAckError if any recovery acknowledgment signature
     * is invalid. Note that this does NOT mean the DKG failed (reaching this
     * point implies the DKG itself was successful). It only means it cannot be
     * confirmed that all participants have a copy of the recovery data.
     */
    fun participantRecoveryAcksVerify(
        recoveryData: ByteArray,
        params: SessionParams,
        ackSigs: List<ByteArray>
    ) {
        paramsValidate(params)
        val hostpubkeys = params.hostpubkeys
        val t = params.t

        if (ackSigs.size != hostpubkeys.size) {
            throw IllegalArgumentException()
        }

        val deserialized = try {
            deserializeRecoveryData(recoveryData)
        } catch (e: Exception) {
            throw RecoveryDataError("Failed to deserialize recovery data")
        }

        if (deserialized.t != t || !hostpubkeysEqual(deserialized.hostpubkeys, hostpubkeys)) {
            throw RecoveryDataError(
                "Recovery data does not match the provided session parameters"
            )
        }

        for ((i, sig) in ackSigs.withIndex()) {
            val rmsg = RecoveryAckMsg.fromBytes(sig)
            val msg = recoveryAckMessage(recoveryData, i)
            val valid = ChillDkgCrypto.schnorrVerify(
                msg,
                // Dropping the sign byte from hostpubkeys[i] is okay because msg
                // commits on the full hostpubkeys[i]: it encodes all hostpubkeys
                // together with the id i.
                hostpubkeys[i].sliceArray(1 until 33),
                rmsg.sig
            )
            if (!valid) {
                throw InvalidRecoveryAckError(i)
            }
        }
    }

    /**
     * Raised if a recovery acknowledgment signature is invalid.
     */
    class InvalidRecoveryAckError(participantId: Int) : FaultyParticipantError(participantId)
}
