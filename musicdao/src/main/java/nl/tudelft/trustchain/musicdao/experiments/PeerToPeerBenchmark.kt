package nl.tudelft.trustchain.musicdao.experiments

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import nl.tudelft.ipv8.IPv4Address
import nl.tudelft.ipv8.android.keyvault.AndroidCryptoProvider
import nl.tudelft.ipv8.keyvault.PrivateKey

class PeerToPeerBenchmark {

    fun run(context: Context) {
        val BENCHMARK_UNTIL = 10
        val RESULTS_AMOUNT = 5

        Log.d("ExperimentsResults", "Starting peer to peer benchmarks...")
        val privateKeys = generateKeys(BENCHMARK_UNTIL)
        val nodesAmount = BENCHMARK_UNTIL

        val nodes = (0 until nodesAmount).map {
            val node = EvaluationNode(it, privateKeys[it])
            node.startIpv8(context)
            node
        }

        nodes.forEach { node ->
            val peers = nodes.map { it.ipv8.myPeer }
            peers.forEach { peer ->
                node.ipv8.network.addVerifiedPeer(peer)
                node.peers.add(peer)
            }
        }

        val initializedMap = mutableMapOf<String, Boolean>()
        nodes.forEach { node ->
            initializedMap[node.ipv8.myPeer.mid] = false
        }

        Log.d("ExperimentsResults", "Waiting for all nodes to initialize...")
        do {
            nodes.forEach { node ->
                val peer = node.ipv8.myPeer
                initializedMap[peer.mid] =
                    peer.wanAddress != IPv4Address.EMPTY && peer.lanAddress != IPv4Address.EMPTY
            }
            Log.d(
                "ExperimentsResults",
                "Initialized nodes: ${initializedMap.values.count { it }} / ${initializedMap.size}"
            )
            Thread.sleep(2_000)
        } while (initializedMap.containsValue(false))
        Log.d("ExperimentsResults", "All nodes initialized! Starting experiment...")

        val results = mutableMapOf<Int, MutableList<Double>>()
        GlobalScope.launch(Dispatchers.Main) {
            repeat((0 until RESULTS_AMOUNT).count()) {
                (2..nodesAmount).map {
                    Log.d("ExperimentsResults", "Running experiment with $it nodes...")
                    val result = runExperiment(nodes, it)
                    results[it] = results[it]?.apply {
                        add(result.first)
                    } ?: mutableListOf(result.first)
                    nodes[0].getMultiSignatureCommunity().clearOnSignatureListeners()
                    Log.d("ExperimentsResults", "Experiment with $it nodes finished!")
                    Log.d("ExperimentsResults", "Result: ${result.first} seconds, valid: ${result.second}")
                }
            }
            val resultsCsv = results.map { (nodes, times) ->
                "$nodes, ${times.joinToString(", ")}"
            }.joinToString("\n")
            Log.d("ExperimentsResults", "Raw results:\n$resultsCsv")
        }
    }

    private suspend fun runExperiment(
        originalNodes: List<EvaluationNode>,
        nodesAmount: Int
    ): Pair<Double, Boolean> =
        suspendCancellableCoroutine { continuation ->
            val start = System.currentTimeMillis()
            val community = originalNodes[0].getMultiSignatureCommunity()
            val cb = fun(valid: Boolean) {
                val end = System.currentTimeMillis()
                val seconds = (end - start) / 1000.0
                continuation.resume(Pair(seconds, valid), {})
            }
            community.registerOnSignatureFinished(cb)
            val participantMids = originalNodes.map { it.ipv8.myPeer.mid }.take(nodesAmount)
            community.createSession("Hello World.", participantMids)
        }

    private fun generateKeys(amount: Int): List<PrivateKey> {
        return (0 until amount).map {
            AndroidCryptoProvider.generateKey()
        }
    }
}

