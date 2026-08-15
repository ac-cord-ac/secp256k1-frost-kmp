package ac.cord.auxiliary.frost

class FrostSecretNonce(
    value: ByteArray
) {
    private var secretNonce: ByteArray? = value.copyOf()

    fun getSecretNonce(): ByteArray {
        return secretNonce ?: throw IllegalArgumentException("The secret nonce has already been used and cleared.")
    }

    fun clear() {
        secretNonce?.fill(0)
        secretNonce = null
    }
}
