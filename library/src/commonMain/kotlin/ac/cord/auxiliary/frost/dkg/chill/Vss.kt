package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import ac.cord.auxiliary.frost.Frost
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.PublicKey

/**
 * A scalar polynomial.
 *
 * A polynomial f of degree at most t - 1 is represented by a list [coeffs] of t
 * coefficients, i.e., f(x) = coeffs[0] + ... + coeffs[t-1] * x^(t-1).
 */
class Polynomial(val coeffs: List<Scalar>) {

    /**
     * Evaluate the polynomial at position [x] (Horner's method).
     */
    fun eval(x: Scalar): Scalar {
        var value = Scalar(BigInteger.ZERO)
        for (coeff in coeffs.asReversed()) {
            value = value.times(x).plus(coeff)
        }
        return value
    }
}

/**
 * A Pedersen VSS commitment: the commitments to the coefficients of a
 * polynomial. Infinity group elements are allowed in a VSS commitment to avoid
 * that a participant can force the sum of valid commitments to be invalid.
 */
class VssCommitment(val ges: List<GroupElement>) {

    fun t(): Int = ges.size

    /**
     * Return commitments to the coefficients of f.
     */
    fun toBytes(): ByteArray {
        return ges.fold(byteArrayOf()) { acc, ge -> acc + ge.toCompressedBytesWithInfinity().value.toByteArray() }
    }

    /**
     * Return the public share of the participant with id [i], i.e., the
     * commitment evaluated at x = i + 1.
     */
    fun pubshare(i: Int): GroupElement {
        // Equivalent to GE.batch_mul((i+1)^j, ges[j]) over all j, with the
        // coefficients reduced modulo the group order.
        var result = GroupElement.INFINITY
        var coeff = BigInteger.ONE
        val base = (i + 1).toBigInteger()
        for (j in ges.indices) {
            result = result.add(ges[j].mul(coeff))
            coeff = coeff.times(base).mod(GroupElement.ORDER)
        }
        return result
    }

    operator fun plus(other: VssCommitment): VssCommitment {
        require(this.t() == other.t())
        return VssCommitment(ges.indices.map { i -> this.ges[i].add(other.ges[i]) })
    }

    fun commitmentToSecret(): GroupElement = ges[0]

    fun commitmentToNonconstTerms(): List<GroupElement> = ges.subList(1, t())

    /**
     * Return a modified VSS commitment such that the threshold public key
     * generated from it has an unspendable BIP 341 Taproot script path.
     *
     * Specifically, for a VSS commitment `com`, we have
     * `com.invalidTaprootCommit().commitmentToSecret() = com.commitmentToSecret() + t*G`,
     * where the tweak `t` commits to an empty message, which is invalid
     * according to BIP 341 for Taproot script spends. This follows BIP 341's
     * recommended approach for committing to an unspendable script path.
     *
     * This prevents a malicious participant from secretly inserting a *valid*
     * Taproot commitment to a script path into the summed VSS commitment during
     * the DKG protocol.
     *
     * @return the updated VSS commitment, the tweak `t` which must be added to
     * all secret shares of the commitment, and the tweak's public share.
     */
    fun invalidTaprootCommit(): Triple<VssCommitment, Scalar, GroupElement> {
        val pk = commitmentToSecret()
        val secshareTweak = Scalar.fromBytesChecked(
            Frost.taggedHash("TapTweak", pk.getX().toByteArray())
        )
        val pubshareTweak = GroupElement.GENERATOR_POINT.mul(secshareTweak.toBigInteger())
        val vssTweak = VssCommitment(listOf(pubshareTweak) + List(t() - 1) { GroupElement.INFINITY })
        return Triple(this + vssTweak, secshareTweak, pubshareTweak)
    }

    companion object {
        fun lenBytes(t: Int): Int = 33 * t

        /**
         * @throws IllegalArgumentException if the byte string is malformed (ValueError in the Python reference).
         */
        fun fromBytes(b: ByteArray, t: Int): VssCommitment {
            if (b.size != lenBytes(t)) {
                throw IllegalArgumentException()
            }
            val ges = (0 until t).map { j ->
                GroupElement.fromCompressedBytesWithInfinity(PublicKey(b.sliceArray(33 * j until 33 * j + 33)))
            }
            return VssCommitment(ges)
        }

        /**
         * The caller needs to provide the correct pubshare(i).
         */
        fun verifySecshare(secshare: Scalar, pubshare: GroupElement): Boolean {
            val actual = GroupElement.GENERATOR_POINT.mul(secshare.toBigInteger())
            return actual == pubshare
        }
    }
}

/**
 * Pedersen's verifiable secret sharing over the scalar field of secp256k1.
 */
class Vss(private val f: Polynomial) {

    /**
     * Return the secret share for the participant with id [i]; this computes f(i+1).
     */
    fun secshareFor(i: Int): Scalar {
        if (i < 0) {
            throw IllegalArgumentException("Invalid participant id: $i")
        }
        val x = Scalar((i + 1).toBigInteger())
        // Ensure we don't compute f(0), which is the secret.
        check(x != Scalar(BigInteger.ZERO))
        return f.eval(x)
    }

    /**
     * Return the secret shares for the participants with ids 0..n-1; this
     * computes [f(1), ..., f(n)].
     */
    fun secshares(n: Int): List<Scalar> = (0 until n).map { secshareFor(it) }

    fun commit(): VssCommitment {
        return VssCommitment(f.coeffs.map { GroupElement.GENERATOR_POINT.mul(it.toBigInteger()) })
    }

    /**
     * Return the secret to be shared; this computes f(0).
     */
    fun secret(): Scalar = f.coeffs[0]

    companion object {
        fun generate(seed: ByteArray, t: Int): Vss {
            val coeffs = (0 until t).map { i ->
                Scalar.fromBytesChecked(
                    taggedHashBipDkg("vss coeffs", seed + i.to4LengthByteArray())
                )
            }
            return Vss(Polynomial(coeffs))
        }
    }
}
