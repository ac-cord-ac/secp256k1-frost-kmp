package ac.cord.auxiliary.extensions

import kotlin.reflect.KClass
import kotlin.test.assertTrue

fun Throwable.testThrowable(expectedException: KClass<out Throwable>, exceptionProcessor: (Throwable) -> Boolean) {
    if (this::class == expectedException) {
        assertTrue(exceptionProcessor(this))
    } else {
        throw AssertionError("Wrong exception raised in a test (expecting=${expectedException}).", this)
    }
}