package ac.cord.auxiliary.cryptography

import fr.acinq.secp256k1.Hex

object CryptographicConstants {
    val p = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").toBigInteger()

    val n = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").toBigInteger()
}