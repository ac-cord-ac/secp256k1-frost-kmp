package ac.cord.auxiliary.exceptions

import com.ionspin.kotlin.bignum.integer.BigInteger

class InvalidContributionException(
    val signerId: BigInteger?,
    val contrib: String,
    reason: Exception?
) : Exception("invalid_contribution($signerId, $contrib)", reason)
