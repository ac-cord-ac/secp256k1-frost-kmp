package ac.cord.auxiliary.frost

import ac.cord.auxiliary.cryptography.CryptographicConstants
import ac.cord.auxiliary.cryptography.Point
import ac.cord.auxiliary.cryptography.pow
import ac.cord.auxiliary.cryptography.to4LengthByteArray
import ac.cord.auxiliary.cryptography.to8LengthByteArray
import ac.cord.auxiliary.cryptography.toBigInteger
import ac.cord.auxiliary.cryptography.toSingleByteByteArray
import ac.cord.auxiliary.cryptography.xor
import ac.cord.auxiliary.exceptions.InvalidContributionException
import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger
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
        messagePrefixed: ByteArray,
        extraIn: ByteArray
    ): Pair<FrostSecretNonce, FrostPublicNonce> {
        val rand = computeRand(rand_, secretShare)

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

        val Rs1 = Point.G.mul(k1)
        val Rs2 = Point.G.mul(k2)

        require(Rs1 != null)
        require(Rs2 != null)

        val frostPublicNonce = FrostPublicNonce(
            Rs1.cbytes() + Rs2.cbytes()
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
            messagePrefixed = message?.let {
                byteArrayOf(0x01) +
                message.size.to8LengthByteArray() + message
            } ?: byteArrayOf(0x00),
            extraIn = extraIn ?: byteArrayOf()
        )
    }

    fun nonceAgg(
        frostPublicNonces: List<FrostPublicNonce>,
        ids: List<ByteVector32>
    ): ByteArray {
        if (frostPublicNonces.size != ids.size) {
            throw IllegalArgumentException("The pubnonces and ids arrays must have the same length.")
        }
        val aggNonce = mutableListOf<ByteArray>()

        for (j in 1..2) {
            var R_j: Point? = null
            ids.zip(frostPublicNonces).forEach { (my_id, publicNonce) ->
                try {
                    val startingIndex =  (j-1)*33
                    val endingIndex = j*32 + (j-1)

                    val R_ij = Point.fromCompressedBytes(publicNonce.value.sliceArray(startingIndex..endingIndex))
                    R_j = R_ij.add(R_j)
                }  catch (e: Throwable) {
                    throw InvalidContributionException(my_id.toBigInteger(), "pubnonce", e)
                }
            }
            if (R_j == null) { // It's infinity...
                aggNonce.add(
                    ByteArray(33)
                )
            } else {
                aggNonce.add(
                    R_j.cbytesExt()
                )
            }

        }
        return aggNonce.flatMap { it.asIterable() }.toByteArray()
    }

    fun deriveInterpolatingValue(identifiers: List<ByteVector32>, myId: ByteVector32): BigInteger {
        if (!identifiers.contains(myId)) {
            throw IllegalArgumentException("The signer's id must be present in the participant identifier list.")
        }
        if (identifiers.toSet().size != identifiers.size) {
            throw IllegalArgumentException("The participant identifier list must contain unique elements.")
        }
        val identifierInteger = myId.toBigInteger()
        require(BigInteger.ONE <= identifierInteger)
        require(identifierInteger < CryptographicConstants.n)


        return deriveInterpolatingValue(
            identifiers.map { it.toBigInteger() },
            identifierInteger
        )
    }

    private fun  deriveInterpolatingValue(identifiers: List<BigInteger>, xI: BigInteger): BigInteger {
        var number: BigInteger = BigInteger.ONE
        var deno = BigInteger.ONE
        for (xJ in identifiers) {
            if (xJ == xI) {
                continue
            }
            number = number.times(xJ) ?: xJ
            deno = deno.times(xJ - xI)
        }
        return number.times(
            deno.pow(CryptographicConstants.n.minus(2), CryptographicConstants.n)
        ).mod(CryptographicConstants.n)
    }

    fun deriveGroupPublicKey(
        publicShares: List<PublicKey>,
        identifiers: List<ByteVector32>
    ): PublicKey {
        require(publicShares.size == identifiers.size)

        var Q: Point? = null
        identifiers.zip(publicShares).forEach { (my_id, publicShare) ->
            val XI = try {
                 Point.fromCompressedBytes(publicShare.value.toByteArray())
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
            val multiple = XI.mul(lamI)
            Q = Q?.add(multiple) ?: multiple
        }
        require(Q != null)
        return PublicKey(
            Q.cbytes()
        )
    }

    fun groupPublicKeyAndTweet(
        publicShares: List<PublicKey>,
        ids: List<ByteVector32>,
        tweaks: List<ByteArray>,
        isXonlies: List<Boolean>
    ): FrostTweakContext {
        if (publicShares.size != ids.size) {
            throw IllegalArgumentException("The pubshares and ids arrays must have the same length.")
        }

        if (tweaks.size != isXonlies.size) {
            throw IllegalArgumentException("The tweaks and is_xonly arrays must have the same length.")
        }

        val groupPublicKey = deriveGroupPublicKey(publicShares, ids)
        var frostTweakContext = FrostTweakContext(groupPublicKey)

        tweaks.zip(isXonlies).forEach { (tweak, isXonly) ->
            frostTweakContext = frostTweakContext.applyTweak(
                ByteVector32(tweak),
                isXonly
            )
        }

        return frostTweakContext
    }


    fun partialSignatureVerify(
        frostPartialSignature: FrostPartialSignature,
        identifiers: List<ByteVector32>,
        frostPublicNonces: List<FrostPublicNonce>,
        publicShares: List<PublicKey>,
        tweaks: List<ByteArray>,
        isXonlies: List<Boolean>,
        message: ByteArray,
        index: Int
    ): Boolean {
        if (identifiers.size != frostPublicNonces.size) {
            throw IllegalArgumentException("The ids, pubnonces and pubshares arrays must have the same length.")
        }
        if (publicShares.size != frostPublicNonces.size) {
            throw IllegalArgumentException("The ids, pubnonces and pubshares arrays must have the same length.")
        }
        if (tweaks.size != isXonlies.size) {
            throw IllegalArgumentException("The tweaks and is_xonly arrays must have the same length.")
        }

        val aggNonce = nonceAgg(
            frostPublicNonces,
            identifiers
        )
        val frostSessionContext = FrostSessionContext(
            aggNonce, identifiers, publicShares,  tweaks, isXonlies, message
        )

        return frostSessionContext.partialSignatureVerify(
            frostPartialSignature,
            identifiers[index],
            frostPublicNonces[index],
            publicShares[index],
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
        my_id: ByteVector32,
        aggothernonce: FrostPublicNonce,
        identifiers: List<ByteVector32>,
        publicShares: List<PublicKey>,
        tweaks: List<ByteArray>,
        isXonlies: List<Boolean>,
        message: ByteArray,
        rand: ByteArray?
    ): Pair<FrostPublicNonce, FrostPartialSignature> {
        val secretShareInteger = secretShare.toBigInteger()

        if (secretShareInteger < BigInteger.ZERO || secretShareInteger > CryptographicConstants.n) {
            throw IllegalArgumentException("The signer's secret share value is out of range.")
        }

        val signerPublicShare = individualPublicKey(secretShare)

        if (publicShares.contains(signerPublicShare)) {
            throw IllegalArgumentException("The signer\\'s pubshare must be included in the list of pubshares.")
        }

        val secShare_ = computeSecretShare(
            rand, secretShare
        )

        val tweakedGroupPublicKey = groupPublicKeyAndTweet(
            publicShares,
            identifiers,
            tweaks,
            isXonlies
        ).getXonlyPublicKey()

        val k_1 = deterministicNonceHash(
            secShare_, aggothernonce.value, tweakedGroupPublicKey, message, 0
        ).mod(CryptographicConstants.n)
        val k_2 = deterministicNonceHash(
            secShare_, aggothernonce.value, tweakedGroupPublicKey, message, 1
        ).mod(CryptographicConstants.n)

        val R_s1 = Point.G.mul(k_1)
        val R_s2 = Point.G.mul(k_2)

        require(R_s1 != null) { "deterministicSign R_s1 can't be null" }
        require(R_s2 != null) { "deterministicSign R_s2 can't be null" }

        val frostPublicNonce = FrostPublicNonce(
            R_s1.cbytes() + R_s2.cbytes()
        )
        val frostSecretNonce = FrostSecretNonce(
            k_1.toByteArray() + k_2.toByteArray()
        )

        try {
            val aggregateNonce = nonceAgg(
                listOf(frostPublicNonce, aggothernonce),
                listOf(my_id)
            )

            val frostSessionContext = FrostSessionContext(
                aggregateNonce,
                identifiers,
                publicShares,
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
        } catch (e: Throwable) {
            throw InvalidContributionException(null, "aggothernonce", e)
        }
    }

    fun deterministicNonceHash(secretShare: ByteArray, aggothernonce: ByteArray, tweakedGroupPublicKey: XonlyPublicKey, message: ByteArray, index: Int): BigInteger {
        val buffer = secretShare + tweakedGroupPublicKey.value.toByteArray() + aggothernonce +
                message.size.to8LengthByteArray() + message +
                byteArrayOf(index.toByte())

        return taggedHash("FROST/deterministic/nonce", buffer).toBigInteger()
    }


    fun individualPublicKey(
        secretKey: ByteArray
    ): PublicKey {
        val d0 = secretKey.toBigInteger()
        if (d0 <= BigInteger.ZERO || d0 >= CryptographicConstants.n) {
            throw IllegalArgumentException("The secret key must be an integer in the range 1..n-1.")
        }
        val P = Point.G.mul(d0)
        require(P != null)
        return PublicKey(
            P.cbytes()
        )

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
        identifiers: List<ByteArray>,
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

        val integerIdentifiers = identifiers.map { it.toBigInteger() }

        for (numberOfSigners in minParticipants..(maxParticipants+1)) {
            val signerSets = integerIdentifiers.combinations(numberOfSigners)
            for (signerSet in signerSets) {
                var groupSecretKey: BigInteger = BigInteger.ZERO
                for (i in signerSet) {
                    val secretShareI = secretShares[i.intValue(false)-1].toBigInteger()
                    val lambdaI = deriveInterpolatingValue(signerSet, i)
                    groupSecretKey += lambdaI.times(secretShareI)
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

