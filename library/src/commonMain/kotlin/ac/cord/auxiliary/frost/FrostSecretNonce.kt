package ac.cord.auxiliary.frost

class FrostSecretNonce(
    value: ByteArray
) {
    private var secretNonce: ByteArray? = value

    fun getSecretNonce(): ByteArray {
        return secretNonce ?: throw IllegalArgumentException("")
    }

    fun clear() {
        secretNonce = null
    }
}