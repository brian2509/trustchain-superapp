package nl.tudelft.trustchain.musicdao.musig

import android.util.Log
import org.bitcoinj.core.ECKey
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.MessageDigest

/**
 * Preliminary MuSig implementation.
 *
 * https://github.com/bitcoinops/taproot-workshop/blob/master/test_framework/musig.py
 * Previous port-work done by currency II group: https://github.com/Tribler/trustchain-superapp/blob/master/currencyii/README.md
 *
 * See https://eprint.iacr.org/2018/068.pdf for the MuSig signature scheme implemented here.
 *
 * This implementation follows the BIP0340 specification: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki. This
 * has some implications in the multi-signature setting:
 * - The final aggregated public key and aggregated nonce key should have a public key which
 *  y-coordinate is even. If after aggregation this it not the case, the public key should be negated
 *  and all the individual nonce's should be negated as well. The same holds for the aggregated
 *  public key.
 *  - This means all public keys are 32 bytes. Note that BigInteger does not always serialize
 *  to correct amount of bytes. Use helper function.
 *  - The aggregated public and nonce key should be "normalized". In bouncy-castle / BitcoinJ, this
 *  is not always the case by default.
 *  - Follow all the other rules specified in the BIP0340 specification (Tagged Hashes, etc.)
 */

class BIP0340MuSig {

    companion object {
        fun generateAggregatedPublicKey(publicKeyList: List<ECPoint>): Triple<ECPoint, MutableMap<ECPoint, ByteArray>, Boolean> {
            val publicKeyListSorted: List<ECPoint> = publicKeyList.sortedBy {
                it.rawXCoord.toBigInteger()
            }

            var L = ByteArray(0)
            for (key in publicKeyListSorted) {
                L += bigIntegerToBytes(key.rawXCoord.toBigInteger(), 32)
            }

            val Lh: ByteArray = MessageDigest.getInstance("SHA-256").digest(L)

            val tweakingValues: MutableMap<ECPoint, ByteArray> = mutableMapOf()
            var Pm: ECPoint? = null

            for (publicKey in publicKeyListSorted) {
                val publicKeyBytes =
                    bigIntegerToBytes(publicKey.rawXCoord.toBigInteger(), 32)
                tweakingValues[publicKey] =
                    MessageDigest.getInstance("SHA-256").digest(Lh + publicKeyBytes)
                val coefficient = BigInteger(1, tweakingValues[publicKey])

                if (Pm == null) {
                    Pm = publicKey.multiply(coefficient)
                } else {
                    Pm = Pm.add(publicKey.multiply(coefficient))
                }
            }

            Pm = Pm!!.normalize()

            var hasBeenNegated = false
            if (!hasEvenY(Pm)) {
                Pm = Pm.negate()
                hasBeenNegated = true
            }

            require(hasEvenY(Pm))

            return Triple(Pm, tweakingValues, hasBeenNegated)
        }

        fun aggregateNonces(noncesList: List<ECPoint>): Pair<ECPoint, Boolean> {
            var Rm = noncesList.reduce(ECPoint::add)

            // We normalize R here and use it as such in PARTIAL SIGNING
            // This means that for VERIFYING the signature (R, s), we also need to return the normalized R.
            Rm = Rm.normalize()

            // Negate if needed:
            var hasBeenNegated = false
            if (Rm.rawYCoord.toBigInteger()
                .mod(BigInteger.valueOf(2)) != BigInteger.ZERO
            ) {
                hasBeenNegated = true
                Rm = Rm.negate()
            }

            require(hasEvenY(Rm))

            return Pair(
                Rm,
                hasBeenNegated
            )
        }

        fun partialSign(
            publicKey: ECKey,
            nonceKey: ECKey,
            Pm: ECKey,
            Rm: ECKey,
            message: ByteArray
        ): BigInteger {
            require(publicKey.pubKeyPoint.isValid)
            require(Pm.isCompressed)
            require(message.size == 32)
            require(nonceKey.privKey != null && nonceKey.privKey != BigInteger.ZERO)
            require(
                Rm.pubKeyPoint.normalize().affineYCoord.toBigInteger()
                    .mod(BigInteger.valueOf(2)) == BigInteger.ZERO
            )

            val e = createDigest(
                Rm.pubKeyPoint,
                Pm.pubKeyPoint,
                message,
            )

            return (
                nonceKey.privKey.add(
                    e.multiply(publicKey.privKey)
                )
                ).mod(ECKey.CURVE.n)
        }

        /**
         * this function computes e, make sure you check specs of Schnorr
         * VERIFY functions to check in which format R, P and msg are in.
         *
         * Here we use:
         * R: 32 bytes, normalizes, affine x coordinate
         * P: 32 bytes, compressed
         * msg: 32 bytes
         *
         * this function needs to be the same in both SIGNING and verifying !!!
         */
        private fun createDigest(
            Rm: ECPoint,
            Pm: ECPoint,
            msg: ByteArray,
        ): BigInteger {
            require(msg.size == 32)

            val hash = taggedHash(
                "BIP0340/challenge",
                bigIntegerToBytes(
                    Rm.rawXCoord.toBigInteger(),
                    32
                ) + bigIntegerToBytes(Pm.rawXCoord.toBigInteger(), 32) + msg
            )

            return BigInteger(
                1,
                hash
            ) % ECKey.CURVE.n
        }

        fun aggregateSignatures(signatures: List<BigInteger>, Rm: ECPoint): ByteArray {
            val r = bigIntegerToBytes(Rm.normalize().rawXCoord.toBigInteger(), 32)
            val s = bigIntegerToBytes(signatures.reduce(BigInteger::add).mod(ECKey.CURVE.n), 32)
            return r + s
        }
    }
}

fun hasEvenY(P: ECPoint): Boolean {
    require(!P.isInfinity) { "P must not be infinite." }
    return P.normalize().yCoord.toBigInteger() % BigInteger.valueOf(2L) == BigInteger.ZERO
}

fun bigIntegerToBytes(b: BigInteger, numBytes: Int): ByteArray {
    require(b.signum() >= 0)
    require(numBytes > 0)
    val src = b.toByteArray()
    val dest = ByteArray(numBytes)
    val isFirstByteOnlyForSign = src[0].toInt() == 0
    val length = if (isFirstByteOnlyForSign) src.size - 1 else src.size
    require(length <= numBytes)
    val srcPos = if (isFirstByteOnlyForSign) 1 else 0
    val destPos = numBytes - length
    System.arraycopy(src, srcPos, dest, destPos, length)
    return dest
}

fun bytesToBigInteger(bytes: ByteArray): BigInteger {
    return BigInteger(1, bytes)
}

fun  printPoint(name: String, P: ECPoint) {
    Log.d(
        "Experiments",
        "$name: (${P.xCoord.toBigInteger().toString(10)}, ${
        P.yCoord.toBigInteger().toString(10)
        }) (has_even: ${
        hasEvenY(
            P
        )
        })"
    )
}

fun printKey(name: String, key: ECKey) {
    Log.d(
        "Experiments",
        "$name: ${key.privKey.toString(10)} (${
        key.pubKeyPoint.xCoord.toBigInteger().toString(10)
        }, ${key.pubKeyPoint.yCoord.toBigInteger().toString(10)}) (has_even: ${
        hasEvenY(
            key.pubKeyPoint
        )
        })"
    )
}

fun splitSignature(signature: ByteArray): Pair<BigInteger, BigInteger> {
    // Check if signature is 64 bytes long
    require(signature.size == 64) { "Signature must be 64 bytes long" }

    // Split signature into r and s values
    val r = BigInteger(1, signature.sliceArray(0 until 32))
    val s = BigInteger(1, signature.sliceArray(32 until 64))

    return Pair(r, s)
}

fun taggedHash(tag: String, msg: ByteArray): ByteArray {
    val tagHash = MessageDigest.getInstance("SHA-256").digest(tag.toByteArray())
    return MessageDigest.getInstance("SHA-256").digest(tagHash + tagHash + msg)
}

fun stringToByteArray(input: String?): ByteArray {
    requireNotNull(input) { "Input must not be null" }

    val byteArray = ByteArray(32)
    val inputBytes = input.toByteArray()
    for (i in inputBytes.indices) {
        byteArray[i] = inputBytes[i]
    }
    return byteArray
}
