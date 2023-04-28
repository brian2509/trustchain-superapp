package nl.tudelft.trustchain.musicdao.experiments

import android.util.Log
import nl.tudelft.trustchain.musicdao.musig.verify.BIP0340Schnorr.BIP0340Schnorr
import nl.tudelft.trustchain.musicdao.musig.BIP0340MuSig
import nl.tudelft.trustchain.musicdao.musig.bigIntegerToBytes
import nl.tudelft.trustchain.musicdao.musig.stringToByteArray
import org.bitcoinj.core.ECKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger

class LocalExperiment {

    fun runExperiment() {
        val BENCHMARK_UNTIL = 1_000
        val RESULTS_AMOUNT = 5

        Log.d("Experiments", "Starting local benchmarks...")
        val nodeAmountToSeconds = mutableMapOf<Int, MutableList<Double>>()
        val validationResults = mutableListOf<Boolean>()

        // We cache the keys to avoid the overhead of generating them.
        val cachedPublicKeys = (0..BENCHMARK_UNTIL).map { ECKey() }
        val cachedNonceKeys = (0..BENCHMARK_UNTIL).map { ECKey() }

        for (resultRun in 0 until RESULTS_AMOUNT) {
            // only take intervals of 20
            val toTest = mutableListOf<Int>()
            for (i in 2..BENCHMARK_UNTIL) {
                if (i == 2) {
                    toTest.add(i)
                } else if (i % 20 == 0) {
                    toTest.add(i)
                }
            }

            for (nodeAmount in toTest) {
                Log.d(
                    "Experiments",
                    "Running local benchmark (${resultRun + 1}/$RESULTS_AMOUNT) with $nodeAmount nodes..."
                )
                val startTime = System.nanoTime()
                val result = runLocallyWithNodeAmount(nodeAmount, cachedPublicKeys, cachedNonceKeys)
                val endTime = System.nanoTime()

                val secondsTaken = (endTime - startTime) / 1000000000.0
                val resultListForNodeAmount = nodeAmountToSeconds[nodeAmount]
                if (resultListForNodeAmount != null) {
                    resultListForNodeAmount.add(secondsTaken)
                } else {
                    nodeAmountToSeconds[nodeAmount] = mutableListOf(secondsTaken)
                }

                // Validate results.
                val valid1 =
                    BIP0340Schnorr.verify(result.message, result.public32, result.signature)
                val valid2 = verifySchnorrTaprootWorkshop(
                    result.aggregatedPublicKey,
                    result.signature,
                    result.message
                )
                validationResults.add(valid1 && valid2)
            }
        }

        val allValid = validationResults.all { it }
        Log.d("Experiments", "All signatures valid: $allValid")
        // make a string which in the first column has the node amount and in the following X columns the result of the X runs
        // make the raw results, no averages or stds
        val rawResults = nodeAmountToSeconds.map { (nodeAmount, seconds) ->
            "$nodeAmount,${seconds.joinToString(",")}"
        }.joinToString("\n")
        Log.d("Experiments", "\n$rawResults")
    }

    private fun runLocallyWithNodeAmount(
        nodeAmount: Int,
        cachedPublicKeys: List<ECKey>,
        cachedNonceKeys: List<ECKey>
    ): LocalBenchmarkResult {
        val NODE_AMOUNT = nodeAmount

        val preTweakedKeys = cachedPublicKeys.take(NODE_AMOUNT)

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

        val preTweakedNonces = cachedNonceKeys.take(NODE_AMOUNT)

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

        val message = stringToByteArray("Hello world")

        val shares = (0 until NODE_AMOUNT).map {
            BIP0340MuSig.partialSign(
                publicKey = postTweakedKeys[it],
                nonceKey = postTweakedNonces[it],
                Pm = ECKey.fromPublicOnly(aggregatedPublicKey, true),
                Rm = ECKey.fromPublicOnly(aggregatedNonce, true),
                message = message
            )
        }

        val signature = BIP0340MuSig.aggregateSignatures(shares, aggregatedNonce)
        val public32 = bigIntegerToBytes(aggregatedPublicKey.rawXCoord.toBigInteger(), 32)

        return LocalBenchmarkResult(
            message,
            public32,
            signature,
            aggregatedPublicKey
        )
    }
}

data class LocalBenchmarkResult(
    val message: ByteArray,
    val public32: ByteArray,
    val signature: ByteArray,
    val aggregatedPublicKey: ECPoint
)
