package ac.cord.auxiliary.frost.dkg.chill

import ac.cord.auxiliary.cryptography.CryptographicConstants
import ac.cord.auxiliary.cryptography.FieldElement
import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.to32LengthByteArray
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.cryptography.xor
import ac.cord.auxiliary.frost.Frost
import com.ionspin.kotlin.bignum.integer.BigInteger
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.crypto.Digest

/**
 * Low-level cryptographic helpers needed by ChillDKG, ported from secp256k1lab
 * (bip340.py, keys.py, ecdh.py). The Schnorr functions support the custom tag
 * prefixes required by ChillDKG (e.g., "BIP DKG/pop message"), which the
 * fr.acinq.secp256k1 binding does not expose.
 */
internal object ChillDkgCrypto {

    /**
     * Return the plain (compressed, 33-byte) public key corresponding to a secret key,
     * see secp256k1lab.keys.pubkey_gen_plain (equivalent to BIP 327's IndividualPubkey).
     *
     * @throws IllegalArgumentException if the secret key is not an integer in the range 1..n-1.
     */
    fun pubkeyGenPlain(seckey: ByteArray): ByteArray {
        val d0 = seckey.toBigInteger()
        if (d0 !in BigInteger.ONE..<GroupElement.ORDER) {
            throw IllegalArgumentException()
        }
        val P = GroupElement.GENERATOR_POINT.mul(d0)
        require(!P.isInfinity)
        return P.toCompressedBytes().value.toByteArray()
    }

    /**
     * BIP 340 Schnorr signature over an arbitrarily long message, with a
     * configurable tag prefix (see secp256k1lab.bip340.schnorr_sign).
     */
    fun schnorrSign(msg: ByteArray, seckey: ByteArray, auxRand: ByteArray, tagPrefix: String = "BIP0340"): ByteArray {
        val d0 = seckey.toBigInteger()
        if (d0 !in BigInteger.ONE..<GroupElement.ORDER) {
            throw IllegalArgumentException()
        }
        if (auxRand.size != 32) {
            throw IllegalArgumentException()
        }
        val n = GroupElement.ORDER
        val P = GroupElement.GENERATOR_POINT.mul(d0)
        require(!P.isInfinity)
        val d = if (P.hasEvenY()) d0 else n.minus(d0)
        val t = d.to32LengthByteArray().xor(Frost.taggedHash("$tagPrefix/aux", auxRand))
        val k0 = Frost.taggedHash("$tagPrefix/nonce", t + P.getX().toByteArray() + msg).toBigInteger().mod(n)
        if (k0 == BigInteger.ZERO) {
            throw RuntimeException("Failure. This happens only with negligible probability.")
        }
        val R = GroupElement.GENERATOR_POINT.mul(k0)
        require(!R.isInfinity)
        val k = if (R.hasEvenY()) k0 else n.minus(k0)
        val e = Frost.taggedHash("$tagPrefix/challenge", R.getX().toByteArray() + P.getX().toByteArray() + msg)
            .toBigInteger().mod(n)
        val sig = R.getX().toByteArray() + (k.plus(e.times(d))).mod(n).to32LengthByteArray()
        check(schnorrVerify(msg, P.getX().toByteArray(), sig, tagPrefix))
        return sig
    }

    /**
     * BIP 340 Schnorr verification over an arbitrarily long message, with a
     * configurable tag prefix (see secp256k1lab.bip340.schnorr_verify).
     */
    fun schnorrVerify(msg: ByteArray, pubkey: ByteArray, sig: ByteArray, tagPrefix: String = "BIP0340"): Boolean {
        if (pubkey.size != 32) {
            throw IllegalArgumentException()
        }
        if (sig.size != 64) {
            throw IllegalArgumentException()
        }
        val P = try {
            GroupElement.liftX(FieldElement.fromBytesChecked(pubkey))
        } catch (e: IllegalArgumentException) {
            return false
        }
        val r = sig.sliceArray(0 until 32).toBigInteger()
        val s = sig.sliceArray(32 until 64).toBigInteger()
        if (r >= CryptographicConstants.p || s >= GroupElement.ORDER) {
            return false
        }
        val e = Frost.taggedHash("$tagPrefix/challenge", sig.sliceArray(0 until 32) + pubkey + msg)
            .toBigInteger().mod(GroupElement.ORDER)
        val R = GroupElement.GENERATOR_POINT.mul(s).add(P.mul(e).negate())
        if (R.isInfinity || !R.hasEvenY() || R.getX().toBigInteger() != r) {
            return false
        }
        return true
    }

    /**
     * ECDH as in libsecp256k1's default hash function: SHA256 over the compressed
     * encoding of the shared point (see secp256k1lab.ecdh.ecdh_libsecp256k1).
     *
     * @throws IllegalArgumentException if the secret key or public key is invalid.
     */
    fun ecdhLibsecp256k1(seckey: ByteArray, pubkey: ByteArray): ByteArray {
        val d = Scalar.fromBytesChecked(seckey)
        val P = GroupElement.fromCompressedBytes(PublicKey(pubkey))
        val sharedSecret = P.mul(d.toBigInteger())
        check(!sharedSecret.isInfinity) // prime-order group
        return Digest.sha256().hash(sharedSecret.toCompressedBytes().value.toByteArray())
    }
}
