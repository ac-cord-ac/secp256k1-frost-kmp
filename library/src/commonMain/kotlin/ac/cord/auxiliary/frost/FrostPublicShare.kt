package ac.cord.auxiliary.frost

data class FrostPublicShare(
    val value: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as FrostPublicShare

        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        return value.contentHashCode()
    }
}
