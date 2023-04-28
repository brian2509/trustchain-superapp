package com.example.musicdao

import nl.tudelft.trustchain.musicdao.experiments.verifySchnorrTaprootWorkshop
import nl.tudelft.trustchain.musicdao.musig.BIP0340MuSig
import nl.tudelft.trustchain.musicdao.musig.bigIntegerToBytes
import nl.tudelft.trustchain.musicdao.musig.verify.BIP0340Schnorr.BIP0340Schnorr
import org.bitcoinj.core.ECKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.junit.Test
import java.math.BigInteger

/**
 * https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
 */
class BIP0340MusigTest {
    @Test
    fun multiSigE2ETest() {
        val NODE_AMOUNT = 5

        val preTweakedKeys = (0..NODE_AMOUNT).map { ECKey() }

        val (aggregatedPublicKey, signerPublicKeyParts, hasBeenNegated) = BIP0340MuSig.generateAggregatedPublicKey(
            preTweakedKeys.map { it.pubKeyPoint }
        )

        val postTweakedKeys = preTweakedKeys.mapIndexed() { index, key ->
            val coefficient = BigInteger(1, signerPublicKeyParts[key.pubKeyPoint])
            val tweakedKey = ECKey.fromPrivate(key.privKey.multiply(coefficient).mod(ECKey.CURVE.n))
            if (hasBeenNegated) {
                val ecSpec: ECNamedCurveParameterSpec =
                    ECNamedCurveTable.getParameterSpec("secp256k1")
                val newSecKey = ecSpec.n.minus(tweakedKey.privKey).mod(ECKey.CURVE.n)
                return@mapIndexed ECKey.fromPrivate(newSecKey)
            } else {
                return@mapIndexed tweakedKey
            }
        }

        val preTweakedNonces = (0..NODE_AMOUNT).map { ECKey() }

        val (aggregatedNonce, nonceHasBeenNegated) = BIP0340MuSig.aggregateNonces(preTweakedNonces.map { it.pubKeyPoint })
        val postTweakedNonces = preTweakedNonces.map { nonce ->
            if (nonceHasBeenNegated) {
                val ecSpec: ECNamedCurveParameterSpec =
                    ECNamedCurveTable.getParameterSpec("secp256k1")
                val newSecKey = ecSpec.n.minus(nonce.privKey).mod(ECKey.CURVE.n)
                val newKey = ECKey.fromPrivate(newSecKey)
                return@map newKey
            } else {
                return@map nonce
            }
        }

        val message = bigIntegerToBytes(
            BigInteger(
                "93434662535470520275467048816983479898182260386103292106211778704208971917999",
                10
            ),
            32
        )

        val shares = (0..NODE_AMOUNT).map {
            BIP0340MuSig.partialSign(
                publicKey = postTweakedKeys[it],
                nonceKey = postTweakedNonces[it],
                Pm = ECKey.fromPublicOnly(aggregatedPublicKey, true),
                Rm = ECKey.fromPublicOnly(aggregatedNonce, true),
                message = message
            )
        }

        val publicKey = aggregatedPublicKey.rawXCoord.toBigInteger().toString(16)
        val nonceKey = aggregatedNonce.rawXCoord.toBigInteger().toString(16)
        val signature = BIP0340MuSig.aggregateSignatures(shares, aggregatedNonce)

        print("Signature: ")
        println(BigInteger(1, signature).toString(16))
        print("Nonce: ")
        println(nonceKey)
        print("Public key: ")
        print(publicKey)

        val public32 = bigIntegerToBytes(aggregatedPublicKey.rawXCoord.toBigInteger(), 32)
        val valid1 = BIP0340Schnorr.verify(message, public32, signature)
        val valid2 = verifySchnorrTaprootWorkshop(aggregatedPublicKey, signature, message)
        assert(valid1)
        assert(valid2)
    }
}
