package nl.tudelft.trustchain.musicdao.experiments

import android.content.Context
import android.util.Log
import com.squareup.sqldelight.android.AndroidSqliteDriver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import nl.tudelft.ipv8.*
import nl.tudelft.ipv8.attestation.trustchain.TrustChainCommunity
import nl.tudelft.ipv8.attestation.trustchain.TrustChainSettings
import nl.tudelft.ipv8.attestation.trustchain.store.TrustChainSQLiteStore
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.messaging.EndpointAggregator
import nl.tudelft.ipv8.messaging.udp.UdpEndpoint
import nl.tudelft.ipv8.peerdiscovery.DiscoveryCommunity
import nl.tudelft.ipv8.peerdiscovery.strategy.PeriodicSimilarity
import nl.tudelft.ipv8.peerdiscovery.strategy.RandomChurn
import nl.tudelft.ipv8.peerdiscovery.strategy.RandomWalk
import nl.tudelft.ipv8.sqldelight.Database
import org.bitcoinj.core.ECKey
import java.net.InetAddress

class EvaluationNode constructor(
    val id: Int,
    val privateKey: PrivateKey,
) {
    private val scope = CoroutineScope(Dispatchers.Default)
    lateinit var ipv8: IPv8
    var peers: MutableList<Peer> = mutableListOf()
    lateinit var ecKey: ECKey

    fun startIpv8(context: Context) {
        val myKey = privateKey
        val myPeer = Peer(myKey)

        val udpEndpoint = UdpEndpoint(8000 + id, InetAddress.getByName("0.0.0.0"))
        val endpoint = EndpointAggregator(udpEndpoint, null)

        val config = IPv8Configuration(
            overlays = listOf(
                createDiscoveryCommunity(),
                createTrustChainCommunity(context),
                createMultiSignatureCommunity()
            ),
            walkerInterval = 1.0
        )

        this.ecKey = ECKey()

        ipv8 = IPv8(endpoint, config, myPeer)
        ipv8.start()

        scope.launch {
            while (true) {
                for ((_, overlay) in ipv8.overlays) {
                    if (overlay is MultiSignatureCommunity) {
                        printPeersInfo(overlay)
                    }
                }
                delay(100_000)
            }
        }

        for ((_, overlay) in ipv8.overlays) {
            if (overlay is MultiSignatureCommunity) {
                printPeersInfo(overlay)
            }
        }
    }

    fun getMultiSignatureCommunity(): MultiSignatureCommunity {
        return ipv8.getOverlay()
            ?: throw IllegalStateException("BenchmarkCommunity is not configured")
    }

    private fun createDiscoveryCommunity(): OverlayConfiguration<DiscoveryCommunity> {
        val randomWalk = RandomWalk.Factory(timeout = 3.0, peers = 20)
        val randomChurn = RandomChurn.Factory()
        val periodicSimilarity = PeriodicSimilarity.Factory()
        return OverlayConfiguration(
            DiscoveryCommunity.Factory(),
            listOf(randomWalk, randomChurn, periodicSimilarity)
        )
    }

    private fun createTrustChainCommunity(context: Context): OverlayConfiguration<TrustChainCommunity> {
        val blockTypesBcDisabled: Set<String> = setOf("eurotoken_join", "eurotoken_trade")
        val settings = TrustChainSettings(blockTypesBcDisabled)
        val driver = AndroidSqliteDriver(Database.Schema, context, "trustchain.db")
        val store = TrustChainSQLiteStore(Database(driver))
        val randomWalk = RandomWalk.Factory()
        return OverlayConfiguration(
            TrustChainCommunity.Factory(settings, store),
            listOf(randomWalk)
        )
    }

    private fun createMultiSignatureCommunity(): OverlayConfiguration<MultiSignatureCommunity> {
        val randomWalk = RandomWalk.Factory(timeout = 3.0, peers = 20)
        return OverlayConfiguration(
            MultiSignatureCommunity.Factory(this),
            listOf(randomWalk)
        )
    }

    private fun log(message: String) {
        Log.d("Experiments", "Node $id: $message")
    }

    private fun printPeersInfo(overlay: Overlay) {
        val peers = overlay.getPeers()
        val myPeerId = overlay.myPeer.mid
        log(overlay::class.simpleName + ": ${peers.size} peers (me: $myPeerId)")
    }
}
