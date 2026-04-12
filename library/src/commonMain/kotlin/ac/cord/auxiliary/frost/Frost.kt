package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.CryptographicConstants
import ac.cord.auxiliary.cryptography.GroupElement
import ac.cord.auxiliary.cryptography.Scalar
import ac.cord.auxiliary.cryptography.requireWithinCurveOrderRange
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import ac.cord.auxiliary.cryptography.to8LengthByteArray
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.cryptography.toSingleByteByteArray
import ac.cord.auxiliary.cryptography.xor
import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.bitcoin.crypto.Digest
import fr.acinq.lightning.utils.secure
import kotlin.random.Random

object Frost {

    private val logger = Logger.withTag("Frost")

    fun taggedHash(tag: String, message: ByteArray): ByteArray {
        val tagHash = Digest.sha256().hash(tag.encodeToByteArray())
        return Digest.sha256().hash(tagHash + tagHash + message)
    }

    fun nonceHash(
        rand: ByteArray,
        publicShare: PublicKey?,
        thresholdPublicKey: XonlyPublicKey?,
        index: Int,
        messagePrefixed: ByteArray,
        extraIn: ByteArray
    ): BigInteger {
        val buffer = rand +
            (publicShare?.let { publicShare.value.size().toSingleByteByteArray() + publicShare.value.toByteArray() }  ?: 0.toSingleByteByteArray()) +
            (thresholdPublicKey?.let { thresholdPublicKey.value.size().toSingleByteByteArray() + thresholdPublicKey.value.toByteArray() } ?: 0.toSingleByteByteArray()) +
            messagePrefixed +
            extraIn.size.to4LengthByteArray() + extraIn +
            byteArrayOf(index.toByte())

        return taggedHash("FROST/nonce", buffer).toBigInteger()
    }

    private fun computeRand(rand_: ByteVector32, secretShare: ByteVector32?): ByteArray { // TODO: Might want to make this ByteVector32
        return secretShare?.toByteArray()?.xor(
            taggedHash("FROST/aux", rand_.toByteArray())
        ) ?: rand_.toByteArray()
    }

    fun nonceGen(
        rand_: ByteVector32,
        secretShare: ByteVector32?,
        publicShare: PublicKey?,
        thresholdPublicKey: XonlyPublicKey?,
        message: ByteArray?,
        extraIn: ByteArray = byteArrayOf()
    ): Pair<FrostSecretNonce, FrostPublicNonce> {
        val rand = computeRand(rand_, secretShare)

        val messagePrefixed = message?.let {
            byteArrayOf(0x01) +
                    message.size.to8LengthByteArray() + message
        } ?: byteArrayOf(0x00)
        val k1 = nonceHash(
            rand,
            publicShare,
            thresholdPublicKey,
            0,
            messagePrefixed,
            extraIn
        ).mod(CryptographicConstants.n)
        val k2 = nonceHash(
            rand,
            publicShare,
            thresholdPublicKey,
            1,
            messagePrefixed,
            extraIn
        ).mod(CryptographicConstants.n)

        require(k1 != BigInteger.ZERO)
        require(k2 != BigInteger.ZERO)

        val Rs1 = GroupElement.GENERATOR_POINT.mul(k1)
        val Rs2 = GroupElement.GENERATOR_POINT.mul(k2)

        require(!Rs1.isInfinity) { "Rs1 can't be infinity" }
        require(!Rs2.isInfinity) { "Rs2 can't be infinity" }

        val frostPublicNonce = FrostPublicNonce(
            Rs1.toCompressedBytes().value.toByteArray() + Rs2.toCompressedBytes().value.toByteArray()
        )
        val frostSecretNonce = FrostSecretNonce(
            k1.toByteArray() + k2.toByteArray()
        )

        return Pair(
            frostSecretNonce,
            frostPublicNonce
        )
    }

    fun nonceGen(secretShare: ByteVector32?, publicShare: PublicKey?, thresholdPublicKey: XonlyPublicKey?, message: ByteArray?, extraIn: ByteArray?): Pair<FrostSecretNonce, FrostPublicNonce> {

        val rand_ = ByteVector32(
            Random.secure().nextBytes(32)
        )
        return nonceGen(
            rand_ = rand_,
            secretShare = secretShare,
            publicShare = publicShare,
            thresholdPublicKey = thresholdPublicKey ,
            message = message,
            extraIn = extraIn ?: byteArrayOf()
        )
    }

    fun nonceAgg(
        frostPublicNonces: List<FrostPublicNonce>
    ): ByteArray {

        val aggNonce = mutableListOf<ByteArray>()

        for (j in 1..2) {
            var R_j = GroupElement.INFINITY
            frostPublicNonces.forEachIndexed { index, publicNonce ->
                val R_ij = try {
                    val startingIndex =  (j-1)*33
                    val endingIndex = j*32 + (j-1) // TODO: use until below so this can be j*33

                    val pubkey = PublicKey(
                        publicNonce.value.sliceArray(startingIndex..endingIndex)
                    )
                    GroupElement.fromCompressedBytes(
                        pubkey
                    )
                }  catch (e: Throwable) {
                    throw InvalidContributionException(index.toBigInteger(), "pubnonce", e)
                }

                R_j = R_j.add(R_ij)
            }
            if (R_j.isInfinity) { // It's infinity...
                aggNonce.add(
                    ByteArray(33)
                )
            } else {
                aggNonce.add(
                    R_j.toCompressedBytesWithInfinity().value.toByteArray()
                )
            }

        }
        return aggNonce.flatMap { it.asIterable() }.toByteArray()
    }

    fun  deriveInterpolatingValue(identifiers: List<Int>, signerIdentifier: Int): Scalar {
        require(identifiers.contains(signerIdentifier)) { "Signer identifier needs to be among identifiers" }

        require(signerIdentifier.toBigInteger() in BigInteger.ZERO..BigInteger.TWO.pow(32)) { "Signer identifier needs to be within supported range" }
        require(identifiers.toSet().size == identifiers.size) { "All identifiers need to be unique" }

        var numerator = Scalar(BigInteger.ONE)
        var denominator = Scalar(BigInteger.ONE)

        for (currentIdentifier in identifiers) {
            if (currentIdentifier == signerIdentifier) {
                continue
            }
            numerator = numerator.times(BigInteger.ONE.plus(currentIdentifier))
            denominator = denominator.times(currentIdentifier.minus(signerIdentifier).toBigInteger())
        }

        return numerator.divide(denominator)
    }

    fun deriveThresholdPublicKey(
        publicShares: List<PublicKey>,
        identifiers: List<Int>
    ): PublicKey {
        require(publicShares.size == identifiers.size)

        var Q = GroupElement.INFINITY

        identifiers.zip(publicShares).forEach { (my_id, publicShare) ->
            val XI = try {
                GroupElement.fromCompressedBytes(publicShare)
            } catch (e: Throwable) {
                throw InvalidContributionException(
                    my_id.toBigInteger(),
                    "pubshare",
                    e
                )
            }

            val lamI = deriveInterpolatingValue(
                identifiers,
                my_id
            )


            val multiple = XI.mul(lamI.toBigInteger())
            Q = Q.add(multiple)
        }
        require(!Q.isInfinity) { "Q cannot be at infinity" }
        return Q.toCompressedBytes()
    }

    fun thresholdPublicKeyAndTweak(
        publicShares: List<PublicKey>,
        ids: List<Int>,
        tweaks: List<ByteVector32>,
        isXonlies: List<Boolean>
    ): FrostTweakContext {
        if (publicShares.size != ids.size) {
            throw IllegalArgumentException("The pubshares and ids arrays must have the same length.")
        }

        val thresholdPublicKey = deriveThresholdPublicKey(publicShares, ids)
        return thresholdPublicKeyAndTweak(
            thresholdPublicKey = thresholdPublicKey,
            tweaks = tweaks,
            isXonlies = isXonlies
        )
    }

    fun thresholdPublicKeyAndTweak(
        thresholdPublicKey: PublicKey,
        tweaks: List<ByteVector32>,
        isXonlies: List<Boolean>
    ): FrostTweakContext {
        if (tweaks.size != isXonlies.size) {
            throw IllegalArgumentException("The tweaks and is_xonly arrays must have the same length.")
        }

        var frostTweakContext = FrostTweakContext(thresholdPublicKey)

        tweaks.zip(isXonlies).forEach { (tweak, isXonly) ->
            frostTweakContext = frostTweakContext.applyTweak(
                tweak,
                isXonly
            )
        }

        return frostTweakContext
    }


    fun partialSignatureVerify(
        frostPartialSignature: FrostPartialSignature,
        frostPublicNonces: List<FrostPublicNonce>,
        frostSignersContext: FrostSignersContext,
        tweaks: List<ByteVector32>,
        isXonlies: List<Boolean>,
        message: ByteArray,
        index: Int
    ): Boolean {
        frostSignersContext.validateSignersContext()

        if (frostSignersContext.publicShares.size != frostSignersContext.identifiers.size || frostSignersContext.publicShares.size != frostPublicNonces.size) {
            throw IllegalArgumentException("The pubnonces and ids arrays must have the same length.")
        }
        if (tweaks.size != isXonlies.size) {
            throw IllegalArgumentException("The tweaks and is_xonly arrays must have the same length.")
        }

        val aggNonce = nonceAgg(
            frostPublicNonces,
        )
        val frostSessionContext = FrostSessionContext(
            frostSignersContext, aggNonce, tweaks, isXonlies, message
        )
        return frostSessionContext.partialSignatureVerify(
            frostPartialSignature,
            frostSignersContext.identifiers[index],
            frostPublicNonces[index],
            frostSignersContext.publicShares[index],
        )
    }

    private fun computeSecretShare(rand: ByteArray?, secretShare: ByteVector32): ByteArray { // TODO: Might want to make this ByteVector32
        return if (rand != null) {
            secretShare.toByteArray().xor(
                taggedHash("FROST/aux", rand)
            )
        } else {
            secretShare.toByteArray()
        }
    }

    fun deterministicSign(
        secretShare: ByteVector32,
        my_id: Int,
        aggothernonce: FrostPublicNonce,
        frostSignersContext: FrostSignersContext,
        tweaks: List<ByteVector32>,
        isXonlies: List<Boolean>,
        message: ByteArray,
        rand: ByteArray?
    ): Pair<FrostPublicNonce, FrostPartialSignature> {
        secretShare.toBigInteger().requireWithinCurveOrderRange("The signer's secret share value is out of range.")

        val secShare_ = computeSecretShare(
            rand, secretShare
        )

        frostSignersContext.validateSignersContext()

        val tweakedThresholdPublicKey = thresholdPublicKeyAndTweak(
            thresholdPublicKey = frostSignersContext.thresholdPublicKey,
            tweaks = tweaks,
            isXonlies = isXonlies
        ).getXonlyPublicKey()

        val k_1 = Scalar.fromBytesWrapping(
            deterministicNonceHash(
                secShare_, aggothernonce.value, tweakedThresholdPublicKey, message, 0
            )
        )
        val k_2 = Scalar.fromBytesWrapping(
            deterministicNonceHash(
                secShare_, aggothernonce.value, tweakedThresholdPublicKey, message, 1
            )
        )

        require(k_1.toBigInteger() != BigInteger.ZERO)
        require(k_2.toBigInteger() != BigInteger.ZERO)

        val R_s1 = GroupElement.GENERATOR_POINT.mul(k_1.toBigInteger())
        val R_s2 = GroupElement.GENERATOR_POINT.mul(k_2.toBigInteger())


        require(!R_s1.isInfinity) { "deterministicSign R_s1 can't be infinity" }
        require(!R_s2.isInfinity) { "deterministicSign R_s2 can't be infinity" }

        val frostPublicNonce = FrostPublicNonce(
            R_s1.toCompressedBytes().value.toByteArray() + R_s2.toCompressedBytes().value.toByteArray()
        )
        val frostSecretNonce = FrostSecretNonce(
            k_1.toByteArray() + k_2.toByteArray()
        )

        val aggregateNonce = try {
            nonceAgg(
                listOf(frostPublicNonce, aggothernonce),
            )
        } catch (e: Throwable) {
            throw InvalidContributionException(null, "aggothernonce", e)
        }

        val frostSessionContext = FrostSessionContext(
            frostSignersContext = frostSignersContext,
            aggregateNonce,
            tweaks,
            isXonlies,
            message
        )
        val partialSignature = frostSessionContext.sign(
            frostSecretNonce,
            secretShare,
            my_id,
        )

        return Pair(
            frostPublicNonce,
            partialSignature
        )
    }

    fun deterministicNonceHash(secretShare: ByteArray, aggothernonce: ByteArray, tweakedThresholdPublicKey: XonlyPublicKey, message: ByteArray, index: Int): ByteArray {

        val buffer = secretShare + aggothernonce + tweakedThresholdPublicKey.value.toByteArray()  +
                message.size.to8LengthByteArray() + message +
                byteArrayOf(index.toByte())

        return taggedHash("FROST/deterministic/nonce", buffer)
    }


    fun individualPublicKey(
        secretKey: ByteVector32
    ): PublicKey {
        val d0 = secretKey.toBigInteger()
        if (d0 !in BigInteger.ONE..<GroupElement.ORDER) {
            throw IllegalArgumentException("The secret key must be an integer in the range 1..n-1.")
        }
        val P = GroupElement.GENERATOR_POINT.mul(d0)
        require(!P.isInfinity) {"P cannot be infinity"}
        return P.toCompressedBytes()

    }

}

