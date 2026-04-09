package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.CryptographicConstants
import ac.cord.auxiliary.cryptography.Point
import ac.cord.auxiliary.cryptography.requireWithinCurveOrderRange
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey

data class FrostSessionContext(
    val aggNonce: ByteArray,
    val identifiers: List<ByteVector32>,
    val publicShares: List<PublicKey>,
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
        if (identifiers != other.identifiers) return false
        if (publicShares != other.publicShares) return false
        if (tweaks != other.tweaks) return false
        if (isXonlies != other.isXonlies) return false
        if (!message.contentEquals(other.message)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = aggNonce.contentHashCode()
        result = 31 * result + identifiers.hashCode()
        result = 31 * result + publicShares.hashCode()
        result = 31 * result + tweaks.hashCode()
        result = 31 * result + isXonlies.hashCode()
        result = 31 * result + message.contentHashCode()
        return result
    }

    fun getSessionValues(): SessionValues {
        val tweakContext = Frost.groupPublicKeyAndTweet(publicShares, identifiers, tweaks, isXonlies)

        val sortedIdentifiers = identifiers.sortedBy { it.toByteArray().toHexString() }
        val concat_ids = sortedIdentifiers.map { it.toByteArray() }.flatMap { it.asIterable() }.toByteArray()

        val b = Frost.taggedHash("FROST/noncecoef", concat_ids + aggNonce + tweakContext.Q.xbytes() + message).toBigInteger().mod(
            CryptographicConstants.n)

        try {
            val R_1 = Point.fromCompressedBytesExt(
                aggNonce.sliceArray(0..32)
            )
            val R_2 = Point.fromCompressedBytesExt(
                aggNonce.sliceArray(33..65)
            )

            val b_multiplied = R_2?.mul(b)
            val R_ = R_1?.add(b_multiplied) ?: b_multiplied
            val R = R_ ?: Point.G

            val e = Frost.taggedHash("BIP0340/challenge", R.xbytes() + tweakContext.Q.xbytes() + message).toBigInteger().mod(CryptographicConstants.n)

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

    fun getSessionInterpolatingValue(signerIdentifier: ByteVector32): BigInteger {
        return Frost.deriveInterpolatingValue(
            identifiers,
            signerIdentifier
        )
    }

    fun sessionHasSignerPublicShare(publicShare: PublicKey): Boolean {

        return publicShares.contains(publicShare)
    }

    fun sign(frostSecretNonce: FrostSecretNonce, secretShare: ByteArray, my_id: ByteVector32): FrostPartialSignature {
        my_id.toBigInteger().requireWithinCurveOrderRange()

        val sessionValues = getSessionValues()

        val k1_ = frostSecretNonce.getSecretNonce().sliceArray(0..31).toBigInteger()
        val k2_ = frostSecretNonce.getSecretNonce().sliceArray(32..63).toBigInteger()

        frostSecretNonce.clear()

        k1_.requireWithinCurveOrderRange("first secnonce value is out of range.")
        k2_.requireWithinCurveOrderRange("'second secnonce value is out of range.")

        val k1 = if (sessionValues.R.hasEvenY()) {
            k1_
        } else {
            CryptographicConstants.n.minus(k1_)
        }
        val k2 = if (sessionValues.R.hasEvenY()) {
            k2_
        } else {
            CryptographicConstants.n.minus(k2_)
        }

        val d_ = secretShare.toBigInteger()
        d_.requireWithinCurveOrderRange()

        val P = Point.G.mul(d_)


        require(P != null) { "P is null" }

        val publicShare = PublicKey(
            P.cbytes()
        )

        if (!sessionHasSignerPublicShare(publicShare)) {
            throw IllegalArgumentException("The signer's pubshare must be included in the list of pubshares.")
        }

        val a = getSessionInterpolatingValue(my_id)
        val g = if (sessionValues.frostTweakContext.Q.hasEvenY()) {
            BigInteger.ONE
        } else {
            CryptographicConstants.n.minus(1)
        }

        val d = g.multiply(sessionValues.frostTweakContext.gacc).times(d_).mod(CryptographicConstants.n)
        val bk2 = sessionValues.b.times(k2)

        val ead = sessionValues.e.times(a).times(d)
        val s = k1.plus(
            bk2
        ).plus(
            ead
        ).mod(
            CryptographicConstants.n
        )
        val frostPartialSignature = FrostPartialSignature(
            ByteVector32(
                s.toByteArray().toHexString().padStart(64, '0')
            )
        )

        val R_s1 = Point.G.mul(k1_)
        val R_s2 = Point.G.mul(k2_)

        require(R_s1 != null) { "sign R_s1 can't be null" }
        require(R_s2 != null) { "sign R_s2 can't be null" }

        val frostPublicNonce = FrostPublicNonce(R_s1.cbytes() + R_s2.cbytes())

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
        my_id: ByteVector32,
        frostPublicNonce: FrostPublicNonce,
        publicShare: PublicKey
    ): Boolean {
        val sessionValues = getSessionValues()

        val s = frostPartialSignature.toBigInteger()

        if (s >= CryptographicConstants.n) {
            return false
        }

        if (!sessionHasSignerPublicShare(publicShare)) {
            throw IllegalArgumentException("The signer's pubshare must be included in the list of pubshares.")
        }

        val R_s1 = Point.fromCompressedBytes(
            frostPublicNonce.value.sliceArray(0..32)
        )
        val R_s2 = Point.fromCompressedBytes(
            frostPublicNonce.value.sliceArray(33..65)
        )

        val Re_s_ = R_s1.add(R_s2.mul(sessionValues.b))
        val Re_s = if (sessionValues.R.hasEvenY()) {
            Re_s_
        } else {
            Re_s_?.negate()
        }

        val P = Point.fromCompressedBytes(publicShare.value.toByteArray())

        val a = getSessionInterpolatingValue(my_id)
        val g = if (sessionValues.frostTweakContext.Q.hasEvenY()) {
            BigInteger.ONE
        } else {
            CryptographicConstants.n - BigInteger.ONE
        }
        val g_ = g.times(sessionValues.frostTweakContext.gacc).mod(CryptographicConstants.n)

        val multiple = P.mul(sessionValues.e.times(a).times(g_).mod(CryptographicConstants.n))
        return Point.G.mul(s) == (Re_s?.add(multiple) ?: multiple)
    }

    fun partialSignatureAggregate(
        partialSignatures: List<ByteArray>,
        identifiers: List<ByteVector32>,
    ): ByteArray {
        if (partialSignatures.size != identifiers.size) {
            throw IllegalArgumentException("The psigs and ids arrays must have the same length.")
        }

        val sessionValues = getSessionValues()

        var s = BigInteger.ZERO

        identifiers.zip(partialSignatures).forEach { (identifier, partialSignature) ->
            val s_i = partialSignature.toBigInteger()
            if (s_i >= CryptographicConstants.n) {
                throw InvalidContributionException(identifier.toBigInteger(), "psig", null)
            }
            s = s.plus(s_i).mod(CryptographicConstants.n)
        }

        val g = if (sessionValues.frostTweakContext.Q.hasEvenY()) {
            BigInteger.ONE
        } else {
            CryptographicConstants.n.minus(BigInteger.ONE)
        }

        s = (s.plus(sessionValues.e.times(g).times(sessionValues.frostTweakContext.tacc))).mod(CryptographicConstants.n)
        return sessionValues.R.xbytes() + s.toByteArray()
    }

    data class SessionValues(
        val frostTweakContext: FrostTweakContext,
        val b: BigInteger,
        val R: Point,
        val e: BigInteger
    )
}