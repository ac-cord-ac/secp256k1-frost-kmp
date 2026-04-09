package ac.cord.auxiliary.frost

object TrustedDealer {

    fun generateFrostKeys(maxParticipants: Int, minParticipants: Int) {
        if (minParticipants < 2 || minParticipants > maxParticipants) {
            throw IllegalArgumentException("values must satisfy: 2 <= min_participants <= max_participants")
        }

        TODO("Generate Frost Keys...")
    }
}