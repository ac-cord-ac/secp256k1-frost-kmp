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
import korlibs.crypto.SecureRandom

object Frost {

    private val logger = Logger.withTag("Frost")

    fun taggedHash(tag: String, message: ByteArray): ByteArray {
        val tagHash = Digest.sha256().hash(tag.encodeToByteArray())
        return Digest.sha256().hash(tagHash + tagHash + message)
    }

    fun nonceHash(
        rand: ByteArray,
        publicShare: PublicKey?,
        groupPublicKey: XonlyPublicKey?,
        index: Int,
        messagePrefixed: ByteArray,
        extraIn: ByteArray
    ): BigInteger {
        val buffer = rand +
            (publicShare?.let { publicShare.value.size().toSingleByteByteArray() + publicShare.value.toByteArray() }  ?: 0.toSingleByteByteArray()) +
            (groupPublicKey?.let { groupPublicKey.value.size().toSingleByteByteArray() + groupPublicKey.value.toByteArray() } ?: 0.toSingleByteByteArray()) +
            messagePrefixed +
            extraIn.size.to4LengthByteArray() + extraIn +
            byteArrayOf(index.toByte())

        return taggedHash("FROST/nonce", buffer).toBigInteger()
    }

    private fun computeRand(rand_: ByteArray, secretShare: ByteArray?): ByteArray {
        return secretShare?.xor(
            taggedHash("FROST/aux", rand_)
        ) ?: rand_
    }

    fun nonceGen(
        rand_: ByteArray,
        secretShare: ByteArray?,
        publicShare: PublicKey?,
        groupPublicKey: XonlyPublicKey?,
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
            groupPublicKey,
            0,
            messagePrefixed,
            extraIn
        ).mod(CryptographicConstants.n)
        val k2 = nonceHash(
            rand,
            publicShare,
            groupPublicKey,
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

    fun nonceGen(secretShare: ByteArray?, publicShare: PublicKey?, groupPublicKey: XonlyPublicKey?, message: ByteArray?, extraIn: ByteArray?): Pair<FrostSecretNonce, FrostPublicNonce> {

        if (secretShare != null && secretShare.size != 32) {
            throw IllegalArgumentException("The optional byte array secshare must have length 32.")
        }

        val rand_ = SecureRandom.nextBytes(32)
        return nonceGen(
            rand_ = rand_,
            secretShare = secretShare,
            publicShare = publicShare,
            groupPublicKey = groupPublicKey ,
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

    fun deriveGroupPublicKey(
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

    fun groupPublicKeyAndTweet(
        publicShares: List<PublicKey>,
        ids: List<Int>,
        tweaks: List<ByteVector32>,
        isXonlies: List<Boolean>
    ): FrostTweakContext {
        if (publicShares.size != ids.size) {
            throw IllegalArgumentException("The pubshares and ids arrays must have the same length.")
        }

        val groupPublicKey = deriveGroupPublicKey(publicShares, ids)
        return groupPublicKeyAndTweet(
            groupPublicKey = groupPublicKey,
            tweaks = tweaks,
            isXonlies = isXonlies
        )
    }

    fun groupPublicKeyAndTweet(
        groupPublicKey: PublicKey,
        tweaks: List<ByteVector32>,
        isXonlies: List<Boolean>
    ): FrostTweakContext {
        if (tweaks.size != isXonlies.size) {
            throw IllegalArgumentException("The tweaks and is_xonly arrays must have the same length.")
        }

        var frostTweakContext = FrostTweakContext(groupPublicKey)

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

        if (frostSignersContext.publicShares.size != frostPublicNonces.size) {
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

    private fun computeSecretShare(rand: ByteArray?, secretShare: ByteArray): ByteArray {
        return if (rand != null) {
            secretShare.xor(
                taggedHash("FROST/aux", rand)
            )
        } else {
            secretShare
        }
    }

    fun deterministicSign(
        secretShare: ByteArray,
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

        logger.d("secShare: ${secShare_.toHexString()}" )
        frostSignersContext.validateSignersContext()

        val tweakedGroupPublicKey = groupPublicKeyAndTweet(
            groupPublicKey = frostSignersContext.groupPublicKey,
            tweaks = tweaks,
            isXonlies = isXonlies
        ).getXonlyPublicKey()
        logger.d("tweaked_tpk: $tweakedGroupPublicKey")

        val k_1 = Scalar.fromBytesWrapping(
            deterministicNonceHash(
                secShare_, aggothernonce.value, tweakedGroupPublicKey, message, 0
            )
        )
        logger.d("k_1: $k_1")
        val k_2 = Scalar.fromBytesWrapping(
            deterministicNonceHash(
                secShare_, aggothernonce.value, tweakedGroupPublicKey, message, 1
            )
        )
        logger.d("k_2: $k_2")

        require(k_1.toBigInteger() != BigInteger.ZERO)
        require(k_2.toBigInteger() != BigInteger.ZERO)

        val R_s1 = GroupElement.GENERATOR_POINT.mul(k_1.toBigInteger())
        logger.d("R_s1: $R_s1")
        val R_s2 = GroupElement.GENERATOR_POINT.mul(k_2.toBigInteger())
        logger.d("R_s2: $R_s2")


        require(!R_s1.isInfinity) { "deterministicSign R_s1 can't be infinity" }
        require(!R_s2.isInfinity) { "deterministicSign R_s2 can't be infinity" }

        val frostPublicNonce = FrostPublicNonce(
            R_s1.toCompressedBytes().value.toByteArray() + R_s2.toCompressedBytes().value.toByteArray()
        )
        logger.d("pubnonce: ${frostPublicNonce.value.toHexString()}" )
        val frostSecretNonce = FrostSecretNonce(
            k_1.toByteArray() + k_2.toByteArray()
        )
        logger.d("secnonce :${frostSecretNonce.getSecretNonce().toHexString()}")

        val aggregateNonce = try {
            nonceAgg(
                listOf(frostPublicNonce, aggothernonce),
            )
        } catch (e: Throwable) {
            throw InvalidContributionException(null, "aggothernonce", e)
        }
        logger.d("aggnonce: ${aggregateNonce.toHexString()}")

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
        logger.d("psig: ${partialSignature.value.toByteArray().toHexString()}")

        return Pair(
            frostPublicNonce,
            partialSignature
        )
    }

    fun deterministicNonceHash(secretShare: ByteArray, aggothernonce: ByteArray, tweakedGroupPublicKey: XonlyPublicKey, message: ByteArray, index: Int): ByteArray {

        val buffer = secretShare + aggothernonce + tweakedGroupPublicKey.value.toByteArray()  +
                message.size.to8LengthByteArray() + message +
                byteArrayOf(index.toByte())

        logger.d("buf: ${buffer.toHexString()}")
        return taggedHash("FROST/deterministic/nonce", buffer)
    }


    fun individualPublicKey(
        secretKey: ByteArray
    ): PublicKey {
        val d0 = secretKey.toBigInteger()
        if (d0 !in BigInteger.ONE..<GroupElement.ORDER) {
            throw IllegalArgumentException("The secret key must be an integer in the range 1..n-1.")
        }
        val P = GroupElement.GENERATOR_POINT.mul(d0)
        require(!P.isInfinity) {"P cannot be infinity"}
        return P.toCompressedBytes()

    }

    fun checkPubSharesCorrectness(
        secretShares: List<ByteArray>,
        publicShares: List<PublicKey>
    ): Boolean {
        if (secretShares.size != publicShares.size) {
            throw IllegalArgumentException("The secshares and pubshares arrays must have the same length.")
        }
        secretShares.zip(publicShares).forEach { (secretShare, publicShare) ->
            val indyKey = individualPublicKey(secretShare)
            if (indyKey != publicShare) {
                return false
            }
        }
        return true
    }

    fun checkGroupPublicKeyCorrectness(
        maxParticipants: Int,
        minParticipants: Int,
        groupPublicKey: PublicKey,
        identifiers: List<Int>,
        secretShares: List<ByteArray>,
        publicShares: List<PublicKey>
    ): Boolean {
        if (minParticipants <= 1) {
            throw IllegalArgumentException("Need at least 2 participants")
        }
        if (maxParticipants < minParticipants) {
            throw IllegalArgumentException("Max participants needs to be greater then min participants")
        }
        if (secretShares.size != publicShares.size) {
            throw IllegalArgumentException("SecretShares and public shares need to be the same length")
        }
        if (publicShares.size != maxParticipants) {
            throw IllegalArgumentException("public shares array needs to match maxPartcipants")
        }



        for (numberOfSigners in minParticipants..(maxParticipants+1)) {
            val signerSets = identifiers.combinations(numberOfSigners)
            for (signerSet in signerSets) {
                var groupSecretKey: BigInteger = BigInteger.ZERO
                for (i in signerSet) {
                    val secretShareI = secretShares[i-1].toBigInteger()
                    val lambdaI = deriveInterpolatingValue(signerSet, i)
                    groupSecretKey += lambdaI.times(secretShareI).toBigInteger()
                }
                val groupSecretKeyBytes = groupSecretKey.mod(CryptographicConstants.n).toByteArray()
                val computedGroupPublicKey = individualPublicKey(groupSecretKeyBytes)
                if (computedGroupPublicKey != groupPublicKey) {
                    return false
                }
            }

        }
        return true
    }


}

fun <T> Iterable<T>.combinations(length: Int): Sequence<List<T>> = sequence {
    val pool = this@combinations.toList()
    val n = pool.size
    if (length > n) return@sequence

    val indices = IntArray(length) { it }
    while (true) {
        yield(indices.map { pool[it] })
        var i = length - 1
        while (i >= 0 && indices[i] == i + n - length) {
            i--
        }
        if (i < 0) return@sequence
        indices[i]++
        for (j in i + 1 until length) {
            indices[j] = indices[j - 1] + 1
        }
    }
}

