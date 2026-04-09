package ac.cord.auxiliary.exceptions

import co.touchlab.kermit.Logger
import com.ionspin.kotlin.bignum.integer.BigInteger

data class InvalidContributionException(
    val signerId: BigInteger?,
    val contrib: String,
    val reason: Throwable?
): Throwable("invalid_contribution($signerId, $contrib)", reason)