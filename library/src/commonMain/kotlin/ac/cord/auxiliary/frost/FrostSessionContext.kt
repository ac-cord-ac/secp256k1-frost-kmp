package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.CryptographicConstants
import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.requireWithinCurveOrderRange
import ac.cord.auxiliary.cryptography.to32LengthByteArray
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey

data class FrostSessionContext(
    val frostSignersContext: FrostSignersContext,
    val aggNonce: ByteArray,
    val tweaks: List<ByteArray>,
    val isXonlies: List<Boolean>,
    val message: ByteArray
) {
    val logger = Logger.withTag("FrostSessionContext")

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as FrostSessionContext

        if (!aggNonce.contentEquals(other.aggNonce)) return false
        if (tweaks != other.tweaks) return false
        if (isXonlies != other.isXonlies) return false
        if (!message.contentEquals(other.message)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = aggNonce.contentHashCode()
        result = 31 * result + tweaks.hashCode()
        result = 31 * result + isXonlies.hashCode()
        result = 31 * result + message.contentHashCode()
        return result
    }

    fun getSessionValues(): SessionValues {
        frostSignersContext.validateSignersContext()

        val tweakContext = Frost.groupPublicKeyAndTweet(frostSignersContext.publicShares, frostSignersContext.identifiers, tweaks, isXonlies)


        val sortedIdentifiers = frostSignersContext.identifiers.map {
            it.to4LengthByteArray()
        }.sortedBy { it.toHexString() }

        val concatIds = sortedIdentifiers.flatMap { it.asIterable() }.toByteArray()

        val temp = concatIds + aggNonce + tweakContext.Q.toXonlyPublicKey().value.toByteArray() + message

        val b = Scalar.fromBytesNonZeroChecked(
            Frost.taggedHash("FROST/noncecoef", temp)
        )
        try {
            val R_1 = GroupElement.fromCompressedBytesWithInfinity(
                PublicKey(
                    aggNonce.sliceArray(0..32)
                )
            )
            val R_2 = GroupElement.fromCompressedBytesWithInfinity(
                PublicKey(
                    aggNonce.sliceArray(33..65)
                )
            )

            val R_ = R_1.add(
                R_2.mul(b.toBigInteger())
            )
            val R = if (R_.isInfinity) {
                GroupElement.GENERATOR_POINT
            } else {
                R_
            }
            val e = Scalar.fromBytesNonZeroChecked(
                Frost.taggedHash(
                    "BIP0340/challenge",
                    R.toXonlyPublicKey().value.toByteArray() + tweakContext.Q.toXonlyPublicKey().value.toByteArray() + message
                )
            )

            return SessionValues(
                frostTweakContext = tweakContext,
                b =  b,
                R = R,
                e = e
            )
        } catch (e: Throwable) {
            throw InvalidContributionException(
                null,
                "aggnonce",
                e
            )
        }
    }

    fun getSessionInterpolatingValue(signerIdentifier: Int): BigInteger {
        return Frost.deriveInterpolatingValue(
            frostSignersContext.identifiers,
            signerIdentifier
        ).toBigInteger()
    }

    fun sessionHasSignerPublicShare(publicShare: PublicKey): Boolean {
        return frostSignersContext.publicShares.contains(publicShare)
    }

    fun sign(frostSecretNonce: FrostSecretNonce, secretShare: ByteArray, my_id: Int): FrostPartialSignature {
        val sessionValues = getSessionValues()

        val k1_ = frostSecretNonce.getSecretNonce().sliceArray(0..31).toBigInteger()
        val k2_ = frostSecretNonce.getSecretNonce().sliceArray(32..63).toBigInteger()

        frostSecretNonce.clear()

        k1_.requireWithinCurveOrderRange("first secnonce value is out of range.")
        k2_.requireWithinCurveOrderRange("'second secnonce value is out of range.")

        val k1 = if (sessionValues.R.hasEvenY()) {
            k1_
        } else {
            k1_.negate()
        }
        val k2 = if (sessionValues.R.hasEvenY()) {
            k2_
        } else {
            k2_.negate()
        }

        val d_ = secretShare.toBigInteger()
        d_.requireWithinCurveOrderRange()

        val P = GroupElement.GENERATOR_POINT.mul(d_)


        require(!P.isInfinity) { "P should not be at infinity" }

        val publicShare = P.toCompressedBytes()

        if (!sessionHasSignerPublicShare(publicShare)) {
            throw IllegalArgumentException("The signer's pubshare must be included in the list of pubshares.")
        }

        // TODO: Signer id check in identifiers...

        val a = getSessionInterpolatingValue(my_id)
        val g = if (sessionValues.frostTweakContext.Q.hasEvenY()) {
            Scalar(
                BigInteger.ONE
            )
        } else {
            Scalar(
                BigInteger.ONE.negate()
            )
        }

        val d = g.times(sessionValues.frostTweakContext.gacc).times(d_)
        val bk2 = sessionValues.b.times(k2)

        val ead = sessionValues.e.times(a).times(d)
        val s = k1.plus(
            bk2.toBigInteger()
        ).plus(
            ead.toBigInteger()
        )
        val frostPartialSignature = FrostPartialSignature(
            ByteVector32(
                s.toByteArray().toHexString().padStart(64, '0')
            )
        )

        val R_s1 = GroupElement.GENERATOR_POINT.mul(k1_)
        val R_s2 = GroupElement.GENERATOR_POINT.mul(k2_)

        require(!R_s1.isInfinity) { "sign R_s1 can't be infinity" }
        require(!R_s2.isInfinity) { "sign R_s2 can't be infinity" }

        val frostPublicNonce = FrostPublicNonce(
            R_s1.toCompressedBytes().value.toByteArray() + R_s2.toCompressedBytes().value.toByteArray()
        )

        require(
            partialSignatureVerify(
                frostPartialSignature = frostPartialSignature,
                my_id = my_id,
                frostPublicNonce = frostPublicNonce,
                publicShare = publicShare
            )
        ){ "Failed to verify partial signature" }

        return frostPartialSignature
    }




    fun partialSignatureVerify(
        frostPartialSignature: FrostPartialSignature,
        my_id: Int,
        frostPublicNonce: FrostPublicNonce,
        publicShare: PublicKey
    ): Boolean {
        val sessionValues = getSessionValues()

        val s = Scalar.fromBytesNonZeroChecked(
            frostPartialSignature.value.toByteArray()
        )


        if (!sessionHasSignerPublicShare(publicShare)) {
            logger.e("publicShare not in shares")
            return false
        }

        if (!frostSignersContext.identifiers.contains(my_id)) {
            logger.e("$my_id not in ${frostSignersContext.identifiers}")
            return false
        }

        val R_s1 = GroupElement.fromCompressedBytes(
            PublicKey(
                frostPublicNonce.value.sliceArray(0..32)
            )
        )
        val R_s2 = GroupElement.fromCompressedBytes(
            PublicKey(
                frostPublicNonce.value.sliceArray(33..65)
            )
        )

        val Re_s_ = R_s1.add(R_s2.mul(sessionValues.b.toBigInteger()))
        val Re_s = if (sessionValues.R.hasEvenY()) {
            Re_s_
        } else {
            Re_s_.negate()
        }

        val P = try {
            GroupElement.fromCompressedBytes(publicShare)
        } catch (e: Throwable) {
            logger.e("Failed to get P: ", e)
            return false
        }

        val a = getSessionInterpolatingValue(my_id)
        val g = if (sessionValues.frostTweakContext.Q.hasEvenY()) {
            Scalar(BigInteger.ONE)
        } else {
            Scalar(BigInteger.ONE.negate())
        }
        val g_ = g.times(sessionValues.frostTweakContext.gacc)

        val multiple = P.mul(sessionValues.e.times(a).times(g_).toBigInteger())

        return GroupElement.GENERATOR_POINT.mul(s.toBigInteger()).toUncompressedBytes()
            .contentEquals(
                (Re_s.add(multiple)).toUncompressedBytes()
            )
    }

    fun partialSignatureAggregate(
        partialSignatures: List<ByteArray>,
        identifiers: List<Int>,
    ): ByteArray {
        if (partialSignatures.size != identifiers.size) {
            throw IllegalArgumentException("The psigs and ids arrays must have the same length.")
        }

        val sessionValues = getSessionValues()

        var s = Scalar(BigInteger.ZERO)

        identifiers.zip(partialSignatures).forEach { (identifier, partialSignature) ->
            val s_i = try {
                Scalar.fromBytesNonZeroChecked(
                    partialSignature
                )
            } catch (e: Throwable) {
                throw InvalidContributionException(identifier.toBigInteger(), "psig", e)
            }
            s = s.plus(s_i)
        }

        val g = if (sessionValues.frostTweakContext.Q.hasEvenY()) {
            Scalar(
                BigInteger.ONE
            )
        } else {
            Scalar(
                BigInteger.ONE.negate()
            )
        }

        s = (s.plus(sessionValues.e.times(g).times(sessionValues.frostTweakContext.tacc)))
        return sessionValues.R.toXonlyPublicKey().value.toByteArray() + s.toByteArray()
    }

    data class SessionValues(
        val frostTweakContext: FrostTweakContext,
        val b: Scalar,
        val R: GroupElement,
        val e: Scalar
    )
}