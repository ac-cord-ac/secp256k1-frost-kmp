package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import fr.acinq.bitcoin.PublicKey

/**
 * EncPedPop: SimplPedPop with encrypted secret shares, so that the shares can
 * be relayed by an untrusted coordinator. Ported from chilldkg_ref/encpedpop.py.
 */
object EncPedPop {

    ///
    /// Encryption
    ///

    fun ecdh(
        seckey: ByteArray,
        myPubkey: ByteArray,
        theirPubkey: ByteArray,
        context: ByteArray,
        sending: Boolean
    ): Scalar {
        var data = ChillDkgCrypto.ecdhLibsecp256k1(seckey, theirPubkey)
        data += if (sending) {
            myPubkey + theirPubkey
        } else {
            theirPubkey + myPubkey
        }
        check(data.size == 32 + 2 * 33)
        data += context
        return Scalar.fromBytesWrapping(taggedHashBipDkg("encpedpop ecdh", data))
    }

    /**
     * Pad for symmetric encryption to ourselves.
     */
    fun selfPad(symkey: ByteArray, nonce: ByteArray, context: ByteArray): Scalar {
        return Scalar.fromBytesWrapping(
            taggedHashBipDkg("encaps_multi self_pad", symkey + nonce + context)
        )
    }

    /**
     * This is effectively the "Hashed ElGamal" multi-recipient KEM described in
     * Section 5 of "Multi-recipient encryption, revisited" by Alexandre Pinto,
     * Bertram Poettering, Jacob C. N. Schuldt (AsiaCCS 2014). Its crucial
     * feature is to feed the index of the enckey to the hash function. The only
     * difference is that we feed also the pubnonce and context data into the
     * hash function.
     */
    fun encapsMulti(
        secnonce: ByteArray,
        pubnonce: ByteArray,
        deckey: ByteArray,
        enckeys: List<ByteArray>,
        context: ByteArray,
        participantId: Int
    ): List<Scalar> {
        val pads = mutableListOf<Scalar>()
        for ((i, enckey) in enckeys.withIndex()) {
            val context_ = i.to4LengthByteArray() + context
            val pad = if (i == participantId) {
                // We're encrypting to ourselves, so we use a symmetrically
                // derived pad to save the ECDH computation.
                selfPad(symkey = deckey, nonce = pubnonce, context = context_)
            } else {
                ecdh(
                    seckey = secnonce,
                    myPubkey = pubnonce,
                    theirPubkey = enckey,
                    context = context_,
                    sending = true
                )
            }
            pads.add(pad)
        }
        return pads
    }

    fun encryptMulti(
        secnonce: ByteArray,
        pubnonce: ByteArray,
        deckey: ByteArray,
        enckeys: List<ByteArray>,
        context: ByteArray,
        participantId: Int,
        plaintexts: List<Scalar>
    ): List<Scalar> {
        val pads = encapsMulti(secnonce, pubnonce, deckey, enckeys, context, participantId)
        if (plaintexts.size != pads.size) {
            throw IllegalArgumentException()
        }
        return plaintexts.zip(pads).map { (plaintext, pad) -> plaintext.plus(pad) }
    }

    fun decapsMulti(
        deckey: ByteArray,
        enckey: ByteArray,
        pubnonces: List<ByteArray>,
        context: ByteArray,
        participantId: Int
    ): List<Scalar> {
        val context_ = participantId.to4LengthByteArray() + context
        val pads = mutableListOf<Scalar>()
        for ((senderId, pubnonce) in pubnonces.withIndex()) {
            val pad = if (senderId == participantId) {
                selfPad(symkey = deckey, nonce = pubnonce, context = context_)
            } else {
                try {
                    ecdh(
                        seckey = deckey,
                        myPubkey = enckey,
                        theirPubkey = pubnonce,
                        context = context_,
                        sending = false
                    )
                } catch (e: IllegalArgumentException) {
                    // Since deckey and enckey are well-formed, the error must
                    // have been triggered by an invalid pubnonce.
                    throw FaultyParticipantOrCoordinatorError(
                        senderId, "invalid public nonce"
                    )
                }
            }
            pads.add(pad)
        }
        return pads
    }

    fun decryptSum(
        deckey: ByteArray,
        enckey: ByteArray,
        pubnonces: List<ByteArray>,
        context: ByteArray,
        participantId: Int,
        sumCiphertexts: Scalar
    ): Scalar {
        if (participantId >= pubnonces.size) {
            throw IndexOutOfBoundsException()
        }
        val pads = decapsMulti(deckey, enckey, pubnonces, context, participantId)
        return sumCiphertexts.minus(pads.scalarSum())
    }

    ///
    /// Messages
    ///

    class ParticipantMsg(
        val simplPmsg: SimplPedPop.ParticipantMsg,
        val pubnonce: ByteArray,
        val encShares: List<Scalar>
    ) {
        fun toBytes(): ByteArray {
            return simplPmsg.toBytes() + pubnonce +
                    encShares.fold(byteArrayOf()) { acc, share -> acc + share.toByteArray() }
        }

        companion object {
            fun lenBytes(t: Int, n: Int): Int = SimplPedPop.ParticipantMsg.lenBytes(t) + 33 + 32 * n

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, t: Int, n: Int): ParticipantMsg {
                if (b.size != lenBytes(t, n)) {
                    throw IllegalArgumentException()
                }

                // Read simpl_pmsg (MsgParseError if invalid)
                val simplPmsgLen = SimplPedPop.ParticipantMsg.lenBytes(t)
                val simplPmsg = SimplPedPop.ParticipantMsg.fromBytes(b.sliceArray(0 until simplPmsgLen), t = t)
                val rest = b.sliceArray(simplPmsgLen until b.size)

                // Read pubnonce (33 bytes)
                val pubnonce = rest.sliceArray(0 until 33)
                val rest2 = rest.sliceArray(33 until rest.size)

                // Read enc_secshares (32*n bytes)
                val encSecshares = try {
                    (0 until n).map { i ->
                        Scalar.fromBytesChecked(rest2.sliceArray(32 * i until 32 * i + 32))
                    }
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid encrypted secret share")
                }

                return ParticipantMsg(simplPmsg, pubnonce, encSecshares)
            }
        }
    }

    class CoordinatorMsg(
        val simplCmsg: SimplPedPop.CoordinatorMsg,
        val pubnonces: List<ByteArray>
    ) {
        fun toBytes(): ByteArray {
            return simplCmsg.toBytes() + pubnonces.fold(byteArrayOf()) { acc, pubnonce -> acc + pubnonce }
        }

        companion object {
            fun lenBytes(t: Int, n: Int): Int = SimplPedPop.CoordinatorMsg.lenBytes(t, n) + 33 * n

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, t: Int, n: Int): CoordinatorMsg {
                if (b.size != lenBytes(t, n)) {
                    throw IllegalArgumentException()
                }

                // Read simpl_cmsg (MsgParseError if invalid)
                val simplCmsgLen = SimplPedPop.CoordinatorMsg.lenBytes(t, n)
                val simplCmsg = SimplPedPop.CoordinatorMsg.fromBytes(b.sliceArray(0 until simplCmsgLen), t = t, n = n)
                val rest = b.sliceArray(simplCmsgLen until b.size)

                // Read pubnonces (33*n bytes)
                val pubnonces = (0 until n).map { i -> rest.sliceArray(33 * i until 33 * i + 33) }

                return CoordinatorMsg(simplCmsg, pubnonces)
            }
        }
    }

    class CoordinatorInvestigationMsg(
        val encPartialSecshares: List<Scalar>,
        val partialPubshares: List<GroupElement>
    ) {
        fun toBytes(): ByteArray {
            val secsharesBytes = encPartialSecshares.fold(byteArrayOf()) { acc, share -> acc + share.toByteArray() }
            val pubsharesBytes = partialPubshares.fold(byteArrayOf()) { acc, p ->
                acc + p.toCompressedBytesWithInfinity().value.toByteArray()
            }
            return secsharesBytes + pubsharesBytes
        }

        companion object {
            fun lenBytes(n: Int): Int = SimplPedPop.CoordinatorInvestigationMsg.lenBytes(n) + 32 * n

            /**
             * @throws IllegalArgumentException if the length is wrong (ValueError in the Python reference).
             * @throws MsgParseError if the contents are malformed.
             */
            fun fromBytes(b: ByteArray, n: Int): CoordinatorInvestigationMsg {
                if (b.size != lenBytes(n)) {
                    throw IllegalArgumentException()
                }

                // Read enc_partial_secshares (32*n bytes)
                val encPartialSecshares = try {
                    (0 until n).map { i ->
                        Scalar.fromBytesChecked(b.sliceArray(32 * i until 32 * i + 32))
                    }
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid encrypted partial secshare")
                }
                val rest = b.sliceArray(32 * n until b.size)

                // Read partial_pubshares (33*n bytes)
                val partialPubshares = try {
                    (0 until n).map { i ->
                        GroupElement.fromCompressedBytesWithInfinity(PublicKey(rest.sliceArray(33 * i until 33 * i + 33)))
                    }
                } catch (e: IllegalArgumentException) {
                    throw MsgParseError("invalid partial pubshare")
                }

                return CoordinatorInvestigationMsg(encPartialSecshares, partialPubshares)
            }
        }
    }

    ///
    /// Participant
    ///

    class ParticipantState(
        val simplState: SimplPedPop.ParticipantState,
        val pubnonce: ByteArray,
        val enckeys: List<ByteArray>,
        val participantId: Int
    )

    class ParticipantInvestigationData(
        val simplBstate: SimplPedPop.ParticipantInvestigationData,
        val encSecshare: Scalar,
        val pads: List<Scalar>
    )

    fun serializeEncContext(t: Int, enckeys: List<ByteArray>): ByteArray {
        return t.to4LengthByteArray() + enckeys.fold(byteArrayOf()) { acc, enckey -> acc + enckey }
    }

    fun participantStep1(
        seed: ByteArray,
        deckey: ByteArray,
        enckeys: List<ByteArray>,
        t: Int,
        participantId: Int,
        random: ByteArray
    ): Pair<ParticipantState, ByteArray> {
        if (t.toLong() >= 1L shl 32) {
            throw IllegalArgumentException()
        }
        if (random.size != 32) {
            throw IllegalArgumentException()
        }
        val n = enckeys.size

        // Derive an encryption nonce and a seed for SimplPedPop.
        //
        // SimplPedPop will use its seed to derive the secret shares, which we will
        // encrypt using the encryption nonce. That means that all entropy used in
        // the derivation of simpl_seed should also be in the derivation of the
        // pubnonce, to ensure that we never encrypt different secret shares with the
        // same encryption pads. The foolproof way to achieve this is to simply
        // derive the nonce from simpl_seed.
        val encContext = serializeEncContext(t, enckeys)
        val simplSeed = taggedHashBipDkg("encpedpop seed", seed + random + encContext)
        val simplAuxRand = taggedHashBipDkg("simplpedpop aux", simplSeed)
        val secnonce = taggedHashBipDkg("encpedpop secnonce", simplSeed)
        val pubnonce = ChillDkgCrypto.pubkeyGenPlain(secnonce)

        val (simplState, simplPmsg, shares) = SimplPedPop.participantStep1(
            simplSeed, t, n, participantId, simplAuxRand
        )
        check(shares.size == n)

        val encShares = encryptMulti(
            secnonce, pubnonce, deckey, enckeys, encContext, participantId, shares
        )
        val simplPmsgParsed = SimplPedPop.ParticipantMsg.fromBytes(simplPmsg, t = t)

        val pmsg = ParticipantMsg(simplPmsgParsed, pubnonce, encShares).toBytes()
        val state = ParticipantState(simplState, pubnonce, enckeys, participantId)
        return Pair(state, pmsg)
    }

    /**
     * @throws FaultyCoordinatorError if the coordinator is faulty.
     * @throws FaultyParticipantOrCoordinatorError if another known participant or the coordinator is faulty.
     * @throws UnknownFaultyParticipantOrCoordinatorError if another unknown participant or the coordinator is faulty.
     */
    fun participantStep2(
        state: ParticipantState,
        deckey: ByteArray,
        cmsg: ByteArray,
        encSecshare: Scalar
    ): Pair<DkgOutput, ByteArray> {
        val simplState = state.simplState
        val pubnonce = state.pubnonce
        val enckeys = state.enckeys
        val participantId = state.participantId
        val cmsgParsed = try {
            CoordinatorMsg.fromBytes(cmsg, t = simplState.t, n = enckeys.size)
        } catch (e: MsgParseError) {
            throw FaultyCoordinatorError(e.message)
        }
        val simplCmsg = cmsgParsed.simplCmsg
        val pubnonces = cmsgParsed.pubnonces

        val reportedPubnonce = pubnonces[participantId]
        if (!reportedPubnonce.contentEquals(pubnonce)) {
            throw FaultyCoordinatorError("Coordinator replied with wrong pubnonce")
        }

        val encContext = serializeEncContext(simplState.t, enckeys)
        val pads = decapsMulti(
            deckey, enckeys[participantId], pubnonces, encContext, participantId
        )
        val secshare = encSecshare.minus(pads.scalarSum())

        val (dkgOutput, eqInput) = try {
            SimplPedPop.participantStep2(
                simplState, simplCmsg.toBytes(), secshare
            )
        } catch (e: UnknownFaultyParticipantOrCoordinatorError) {
            val simplInvData = e.invData as SimplPedPop.ParticipantInvestigationData
            // Translate simplpedpop.ParticipantInvestigationData into our own
            // encpedpop.ParticipantInvestigationData.
            val invData = ParticipantInvestigationData(simplInvData, encSecshare, pads)
            throw UnknownFaultyParticipantOrCoordinatorError(invData, e.message)
        }

        val eqInputFull = eqInput +
                enckeys.fold(byteArrayOf()) { acc, enckey -> acc + enckey } +
                pubnonces.fold(byteArrayOf()) { acc, pubnonce -> acc + pubnonce }
        return Pair(dkgOutput, eqInputFull)
    }

    /**
     * This function does not return normally. Instead, it raises one of
     * [FaultyParticipantOrCoordinatorError] or [FaultyCoordinatorError].
     */
    fun participantInvestigate(
        error: UnknownFaultyParticipantOrCoordinatorError,
        cinv: ByteArray
    ): Nothing {
        val invData = error.invData as ParticipantInvestigationData
        val simplInvData = invData.simplBstate
        val encSecshare = invData.encSecshare
        val pads = invData.pads
        val cinvParsed = try {
            CoordinatorInvestigationMsg.fromBytes(cinv, n = simplInvData.n)
        } catch (e: MsgParseError) {
            throw FaultyCoordinatorError(e.message)
        }
        val encPartialSecshares = cinvParsed.encPartialSecshares
        val partialPubshares = cinvParsed.partialPubshares
        val partialSecshares = encPartialSecshares.zip(pads).map { (encPartialSecshare, pad) ->
            encPartialSecshare.minus(pad)
        }

        val simplCinv = SimplPedPop.CoordinatorInvestigationMsg(partialPubshares)
        try {
            SimplPedPop.participantInvestigate(
                UnknownFaultyParticipantOrCoordinatorError(simplInvData),
                simplCinv.toBytes(),
                partialSecshares
            )
        } catch (e: SimplPedPop.SecshareSumError) {
            // The secshare is not equal to the sum of the partial secshares in the
            // investigation message. Since the encryption is additively homomorphic,
            // this can only happen if the sum of the *encrypted* secshare is not
            // equal to the sum of the encrypted partial secshares, which is the
            // coordinator's fault.
            check(encPartialSecshares.scalarSum() != encSecshare)
            throw FaultyCoordinatorError(
                "Sum of encrypted partial secshares not equal to encrypted secshare"
            )
        }
    }

    ///
    /// Coordinator
    ///

    class CoordinatorStepResult(
        val cmsg: CoordinatorMsg,
        val dkgOutput: DkgOutput,
        val eqInput: ByteArray,
        val encSecshares: List<Scalar>
    )

    /**
     * @throws FaultyParticipantError if a participant is faulty.
     */
    fun coordinatorStep(
        pmsgs: List<ByteArray>,
        t: Int,
        enckeys: List<ByteArray>
    ): CoordinatorStepResult {
        val n = enckeys.size
        if (n != pmsgs.size) {
            throw IllegalArgumentException()
        }

        val pmsgsParsed = pmsgs.mapIndexed { i, pmsg ->
            try {
                ParticipantMsg.fromBytes(pmsg, t = t, n = n)
            } catch (e: MsgParseError) {
                throw FaultyParticipantError(i, e.message)
            }
        }
        val (simplCmsg, dkgOutput, eqInput) = SimplPedPop.coordinatorStep(
            pmsgs = pmsgsParsed.map { it.simplPmsg.toBytes() }, t = t, n = n
        )
        val simplCmsgParsed = SimplPedPop.CoordinatorMsg.fromBytes(simplCmsg, t = t, n = n)
        val pubnonces = pmsgsParsed.map { it.pubnonce }
        val encSecshares = (0 until n).map { i ->
            pmsgsParsed.map { it.encShares[i] }.scalarSum()
        }
        val eqInputFull = eqInput +
                enckeys.fold(byteArrayOf()) { acc, enckey -> acc + enckey } +
                pubnonces.fold(byteArrayOf()) { acc, pubnonce -> acc + pubnonce }

        // In ChillDKG, the coordinator needs to broadcast the entire enc_secshares
        // array to all participants. But in pure EncPedPop, the coordinator needs to
        // send to each participant i only their entry enc_secshares[i].
        //
        // Since broadcasting the entire array is not necessary, we don't include it
        // in encpedpop.CoordinatorMsg, but only return it as a side output, so that
        // chilldkg.coordinatorStep1 can pick it up. Implementations of pure
        // EncPedPop will need to decide how to transmit enc_secshares[i] to
        // participant i for participantStep2(); we leave this unspecified.
        return CoordinatorStepResult(
            CoordinatorMsg(simplCmsgParsed, pubnonces),
            dkgOutput,
            eqInputFull,
            encSecshares
        )
    }

    fun coordinatorInvestigate(pmsgs: List<ByteArray>, t: Int): List<ByteArray> {
        val n = pmsgs.size
        val pmsgsParsed = pmsgs.map { ParticipantMsg.fromBytes(it, t = t, n = n) }
        val simplPmsgs = pmsgsParsed.map { it.simplPmsg.toBytes() }

        val allEncPartialSecshares = (0 until n).map { i ->
            pmsgsParsed.map { it.encShares[i] }
        }
        val simplCinvs = SimplPedPop.coordinatorInvestigate(simplPmsgs, t)
        val simplCinvsParsed = simplCinvs.map {
            SimplPedPop.CoordinatorInvestigationMsg.fromBytes(it, n = n)
        }
        return (0 until n).map { i ->
            CoordinatorInvestigationMsg(
                allEncPartialSecshares[i], simplCinvsParsed[i].partialPubshares
            ).toBytes()
        }
    }
}
