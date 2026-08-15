package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.frost.Frost

/**
 * Domain separation tag prefix for all ChillDKG tagged hashes (see util.py's BIP_TAG).
 */
const val BIP_TAG: String = "BIP DKG/"

/**
 * Tagged hash with the [BIP_TAG] prefix, see util.py's tagged_hash_bip_dkg.
 */
fun taggedHashBipDkg(tag: String, msg: ByteArray): ByteArray {
    return Frost.taggedHash(BIP_TAG + tag, msg)
}

/**
 * Base exception for errors caused by received protocol messages.
 */
open class ProtocolError(message: String? = null) : Exception(message)

/**
 * Raised if a participant is faulty.
 *
 * This exception is raised by the coordinator code when it detects faulty
 * behavior by a participant, i.e., a participant has deviated from the
 * protocol. Assuming protocol messages have been transmitted correctly and the
 * coordinator itself is not faulty, this exception implies that the participant
 * is indeed faulty.
 *
 * This exception is raised only by the coordinator code. Some faulty behavior
 * by participants will be detected by the other participants instead. See
 * [FaultyParticipantOrCoordinatorError] for details.
 */
open class FaultyParticipantError(
    val participantId: Int,
    message: String? = null
) : ProtocolError(message)

/**
 * Raised if another known participant or the coordinator is faulty.
 *
 * This exception is raised by the participant code when it detects what looks
 * like faulty behavior by a suspected participant. Importantly, this exception
 * is not proof that the suspected participant is indeed faulty. It is instead
 * possible that the coordinator has deviated from the protocol in a way that
 * makes it look as if the suspected participant has deviated from the protocol.
 *
 * This exception is raised only by the participant code. Some faulty behavior
 * by participants will be detected by the coordinator instead. See
 * [FaultyParticipantError] for details.
 */
class FaultyParticipantOrCoordinatorError(
    val participantId: Int,
    message: String? = null
) : ProtocolError(message)

/**
 * Raised if the coordinator is faulty.
 *
 * This exception is raised by the participant code when it detects faulty
 * behavior by the coordinator, i.e., the coordinator has deviated from the
 * protocol. Assuming protocol messages have been transmitted correctly and the
 * raising participant is not faulty, this exception implies that the
 * coordinator is indeed faulty.
 */
class FaultyCoordinatorError(message: String? = null) : ProtocolError(message)

/**
 * Raised if another unknown participant or the coordinator is faulty.
 *
 * This exception is raised by the participant code when it detects what looks
 * like faulty behavior by some other participant, but there is insufficient
 * information to determine which participant should be suspected.
 *
 * To determine a suspected participant, the raising participant may choose to
 * run the optional investigation procedure of the protocol, which requires
 * obtaining an investigation message from the coordinator. See
 * [ChillDkg.participantInvestigate] for details.
 *
 * This is only raised for specific faulty behavior by another participant which
 * cannot be attributed to another participant without further help of the
 * coordinator (namely, sending invalid encrypted secret shares).
 *
 * [invData] holds the information required to perform the investigation.
 */
class UnknownFaultyParticipantOrCoordinatorError(
    val invData: Any?,
    message: String? = null
) : ProtocolError(message)

/**
 * Raised when a protocol message cannot be parsed.
 *
 * Equivalent to the Python reference's MsgParseError, which subclasses
 * ValueError, hence this subclasses [IllegalArgumentException].
 */
class MsgParseError(message: String? = null) : IllegalArgumentException(message)
