package nl.tudelft.trustchain.musicdao.experiments

import nl.tudelft.trustchain.musicdao.musig.bigIntegerToBytes
import nl.tudelft.trustchain.musicdao.musig.hasEvenY
import nl.tudelft.trustchain.musicdao.musig.taggedHash
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger

/**
 * Ported from: https://github.com/bitcoinops/taproot-workshop/blob/master/test_framework/key.py
 */
fun verifySchnorrTaprootWorkshop(publicKey: ECPoint, sig: ByteArray, msg: ByteArray): Boolean {
    require(msg.size == 32)
    require(sig.size == 64)

    val ecSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val r = BigInteger(1, sig.copyOfRange(0, 32))
    if (r >= ecSpec.curve.field.characteristic) {
        return false
    }
    val s = BigInteger(1, sig.copyOfRange(32, 64))
    if (s >= ecSpec.n) {
        return false
    }
    val publicKeyBytes = bigIntegerToBytes(publicKey.xCoord.toBigInteger(), 32)
    val e = BigInteger(
        1,
        taggedHash("BIP0340/challenge", sig.copyOfRange(0, 32) + publicKeyBytes + msg)
    ).mod(ecSpec.n)
    val R = ecSpec.g.multiply(s).add(publicKey.multiply(ecSpec.n.subtract(e))).normalize()
    if (!hasEvenY(R)) {
        return false
    }
    if (r != R.normalize().rawXCoord.toBigInteger()) {
        return false
    }
    return true
}
