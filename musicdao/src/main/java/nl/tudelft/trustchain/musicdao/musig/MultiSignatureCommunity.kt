package nl.tudelft.trustchain.musicdao.experiments

import android.util.Log
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import nl.tudelft.ipv8.Community
import nl.tudelft.ipv8.Overlay
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.messaging.Packet
import nl.tudelft.trustchain.musicdao.musig.verify.BIP0340Schnorr.BIP0340Schnorr
import nl.tudelft.trustchain.musicdao.musig.*
import org.bitcoinj.core.ECKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import java.util.*

@kotlinx.serialization.Serializable
data class ParticipantInformation(
    var publicKey33: ByteArray?,
    var nonceKey33: ByteArray?,
    var partialSignature: ByteArray?
) {
    companion object {
        fun createEmpty(): ParticipantInformation {
            return ParticipantInformation(null, null, null)
        }
    }
}

@kotlinx.serialization.Serializable
data class Session(
    val id: String,
    val message: ByteArray,
    val participantsMids: MutableList<String>,
)

@kotlinx.serialization.Serializable
data class SessionPrivate(
    val id: String,
    val message: ByteArray,
    val participants: MutableMap<String, ParticipantInformation>,
    val aggregatedPublicKey33: ByteArray? = null,
    val aggregatedNonce33: ByteArray? = null,
    val finalSignature: ByteArray? = null,
) {
    companion object {
        fun createEmpty(
            id: String,
            message: ByteArray,
            participantsMids: MutableList<String>
        ): SessionPrivate {
            val participants = mutableMapOf<String, ParticipantInformation>()
            participantsMids.forEach {
                participants[it] = ParticipantInformation.createEmpty()
            }
            return SessionPrivate(id, message, participants)
        }
    }
}

@kotlinx.serialization.Serializable
data class PublicKeyResponse(
    val sessionId: String,
    val publicKey33: ByteArray
)

@kotlinx.serialization.Serializable
data class NonceKeyResponse(
    val sessionId: String,
    val nonceKey33: ByteArray?
)

@kotlinx.serialization.Serializable
data class PartialSignatureResponse(
    val sessionId: String,
    val signature64: ByteArray?
)

class MultiSignatureCommunity constructor(val evaluationNode: EvaluationNode) : Community() {
    override val serviceId = "02313633c1912a121279f8248fc8db5899c5df5a"
    private val privateKey: ECKey = evaluationNode.ecKey
    private val nonces = mutableMapOf<String, ECKey>()

    private val sessions = mutableMapOf<String, Session>()
    private val sessionsPrivate = mutableMapOf<String, SessionPrivate>()

    private val partialSignatureRequestsWaiting = mutableMapOf<Pair<String, String>, Packet>()
    private val signatureFinishedEventListeners = mutableListOf<(Boolean) -> Unit>()

    private val outstandingCache = mutableMapOf<Pair<String, String>, MutableSet<Int>>()

    init {
        messageHandlers[ON_REQUEST_PUBLIC_KEY] = ::onRequestPublicKey
        messageHandlers[ON_RECEIVE_PUBLIC_KEY] = ::onReceivePublicKey
        messageHandlers[ON_REQUEST_NONCE] = ::onRequestNonce
        messageHandlers[ON_RECEIVE_NONCE] = ::onReceiveNonce
        messageHandlers[ON_PARTIAL_SIGNATURE_REQUEST] = ::onReceivePartialSignatureRequest
        messageHandlers[ON_RECEIVE_PARTIAL_SIGNATURE_REQUEST] = ::onReceivePartialSignature
    }

    fun createSession(message: String, participantsMids: List<String>) {
        val uuid = UUID.randomUUID().toString()

        val session = Session(
            id = uuid,
            message = stringToByteArray(message),
            participantsMids = participantsMids.toMutableList()
        )

        val sessionPrivate = SessionPrivate.createEmpty(
            uuid,
            stringToByteArray(message),
            participantsMids.toMutableList()
        )

        sessions[uuid] = session
        sessionsPrivate[uuid] = sessionPrivate

        tryAndRequestPublicKeys(uuid)
    }

    private fun tryAndRequestPublicKeys(id: String) {
        val session = getSession(id)!!

        // add my public key
        sessionsPrivate[session.id]!!.participants[myPeer.mid] =
            sessionsPrivate[session.id]!!.participants[myPeer.mid]!!.copy(
                publicKey33 = privateKey.pubKeyPoint.getEncoded(true)
            )

        // count how many public keys we have and we need
        val publicKeysCount =
            session.participantsMids.count { sessionsPrivate[session.id]!!.participants[it]!!.publicKey33 != null }
        val publicKeysNeeded = session.participantsMids.size

        val mids =
            session.participantsMids.filter { sessionsPrivate[session.id]!!.participants[it]!!.publicKey33 == null }
        val midsOutstanding =
            session.participantsMids.filter {
                outstandingCache[Pair(session.id, it)]?.contains(
                    ON_RECEIVE_PUBLIC_KEY
                ) == true
            }

        val midsToRequest = mids.filter { !midsOutstanding.contains(it) }
        log("tryAndRequestPublicKeys: keys count: $publicKeysCount/$publicKeysNeeded, mids: ${mids.size}, midsOutstanding: ${midsOutstanding.size} midsToRequest: ${midsToRequest.size}")

        midsToRequest.forEach {
            val peer = findPeer(it)
            if (peer != null) {
                val json = Json.encodeToString(session)
                val packet = serializePacket(ON_REQUEST_PUBLIC_KEY, StringMessage(json))
                log("Sending public key request to ${peer.mid}")
                send(peer, packet)

                // add ACK waiting for public key from peer
                outstandingCache.getOrPut(Pair(session.id, it)) { mutableSetOf() }
                    .add(ON_RECEIVE_PUBLIC_KEY)
            }
        }
    }

    /**
     * Treat this as the packet which introduces / invites users to musig
     * i.e. validate the message and respond if they want to join
     */
    private fun onRequestPublicKey(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(StringMessage.Deserializer)
        val receivedSession = Json.decodeFromString<Session>(payload.message)
        log("Received public key request from ${peer.mid}")

        if (getSession(receivedSession.id) == null) {
            sessions[receivedSession.id] = receivedSession
        }
        if (getSessionPrivate(receivedSession.id) == null) {
            val sessionPrivate = SessionPrivate.createEmpty(
                receivedSession.id,
                receivedSession.message,
                receivedSession.participantsMids
            )
            sessionsPrivate[receivedSession.id] = sessionPrivate
        }

        val session = getSession(receivedSession.id)!!

        // add my public key
        sessionsPrivate[session.id]!!.participants[myPeer.mid] =
            sessionsPrivate[session.id]!!.participants[myPeer.mid]!!.copy(
                publicKey33 = privateKey.pubKeyPoint.getEncoded(true)
            )

        val publicKeyResponse = PublicKeyResponse(
            sessionId = session.id,
            publicKey33 = privateKey.pubKeyPoint.getEncoded(true)
        )

        log("Sending public key to ${peer.mid}")
        val json = Json.encodeToString(publicKeyResponse)
        val packet = serializePacket(ON_RECEIVE_PUBLIC_KEY, StringMessage(json))
        send(peer, packet)

        tryAndRequestPublicKeys(publicKeyResponse.sessionId)
    }

    private fun onReceivePublicKey(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(StringMessage.Deserializer)
        val publicKeyResponse = Json.decodeFromString<PublicKeyResponse>(payload.message)

        val session = getSession(publicKeyResponse.sessionId)!!

        // add my public key
        sessionsPrivate[session.id]!!.participants[myPeer.mid] =
            sessionsPrivate[session.id]!!.participants[myPeer.mid]!!.copy(
                publicKey33 = privateKey.pubKeyPoint.getEncoded(true)
            )

        // add received public key to private session
        sessionsPrivate[publicKeyResponse.sessionId]!!.participants[peer.mid]!!.publicKey33 =
            publicKeyResponse.publicKey33

        val allPublicKeys =
            session.participantsMids.all { sessionsPrivate[session.id]!!.participants[it]!!.publicKey33 != null }

        // in case partial signature relied on missing public key, try again
        if (partialSignatureRequestsWaiting[Pair(publicKeyResponse.sessionId, peer.mid)] != null) {
            onReceivePartialSignatureRequest(
                partialSignatureRequestsWaiting[
                    Pair(
                        publicKeyResponse.sessionId,
                        peer.mid
                    )
                ]!!
            )
        }

        tryAndRequestPublicKeys(publicKeyResponse.sessionId)

        if (allPublicKeys) {
            log("All public keys received, requesting nonces")
            tryAndRequestNonces(publicKeyResponse.sessionId)
        }
    }

    private fun tryAndRequestNonces(sessionId: String) {
        val session = getSession(sessionId)!!

        // create nonce if we don't have one
        val nonce = if (nonces[session.id] == null) {
            val nonce = ECKey()
            nonces[session.id] = nonce
            nonce
        } else {
            nonces[session.id]!!
        }

        // add my nonce
        sessionsPrivate[session.id]!!.participants[myPeer.mid] =
            sessionsPrivate[session.id]!!.participants[myPeer.mid]!!.copy(
                nonceKey33 = nonce.pubKeyPoint.getEncoded(true)
            )

        // log how many nonces we have and we need
        val noncesCount =
            session.participantsMids.count { sessionsPrivate[session.id]!!.participants[it]!!.nonceKey33 != null }
        val noncesNeeded = session.participantsMids.size

        // check which nonces we still need
        val mids =
            session.participantsMids.filter { sessionsPrivate[session.id]!!.participants[it]!!.nonceKey33 == null }
        val midsOutstanding =
            session.participantsMids.filter {
                outstandingCache[Pair(session.id, it)]?.contains(
                    ON_RECEIVE_NONCE
                ) == true
            }

        val midsToRequest = mids.filter { !midsOutstanding.contains(it) }
        log("tryAndRequestNonces: nonces count: $noncesCount/$noncesNeeded, mids: ${mids.size}, midsOutstanding: ${midsOutstanding.size} midsToRequest: ${midsToRequest.size}")

        midsToRequest.forEach {
            val peer = findPeer(it)
            if (peer != null) {
                val packet = serializePacket(ON_REQUEST_NONCE, StringMessage(sessionId))
                log("Sending nonce request to ${peer.mid}")
                send(peer, packet)

                // add ACK waiting for nonce from peer
                outstandingCache.getOrPut(Pair(session.id, peer.mid)) { mutableSetOf() }
                    .add(ON_RECEIVE_NONCE)
            }
        }
    }

    private fun onRequestNonce(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(StringMessage.Deserializer)
        val receivedSessionId = payload.message

        val session = getSession(receivedSessionId)!!

        val nonce = if (nonces[receivedSessionId] == null) {
            val nonce = ECKey()
            nonces[receivedSessionId] = nonce
            nonce
        } else {
            nonces[receivedSessionId]!!
        }

        // add my nonce
        sessionsPrivate[session.id]!!.participants[myPeer.mid] =
            sessionsPrivate[session.id]!!.participants[myPeer.mid]!!.copy(
                nonceKey33 = nonce.pubKeyPoint.getEncoded(true)
            )

        val nonceResponse = NonceKeyResponse(
            sessionId = receivedSessionId,
            nonceKey33 = nonce.pubKeyPoint.getEncoded(true)
        )

        val json = Json.encodeToString(nonceResponse)
        val packet = serializePacket(ON_RECEIVE_NONCE, StringMessage(json))
        log("Sending nonce to $${peer.mid}")
        send(peer, packet)

        tryAndRequestNonces(nonceResponse.sessionId)
    }

    private fun onReceiveNonce(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(StringMessage.Deserializer)
        val nonceKeyResponse = Json.decodeFromString<NonceKeyResponse>(payload.message)

        val session = getSession(nonceKeyResponse.sessionId)!!

        // create nonce if we don't have one
        val nonce = if (nonces[nonceKeyResponse.sessionId] == null) {
            val nonce = ECKey()
            nonces[nonceKeyResponse.sessionId] = nonce
            nonce
        } else {
            nonces[nonceKeyResponse.sessionId]!!
        }

        // add my nonce
        sessionsPrivate[session.id]!!.participants[myPeer.mid] =
            sessionsPrivate[session.id]!!.participants[myPeer.mid]!!.copy(
                nonceKey33 = nonce.pubKeyPoint.getEncoded(true)
            )

        // add received nonce to private session
        sessionsPrivate[nonceKeyResponse.sessionId]!!.participants[peer.mid]!!.nonceKey33 =
            nonceKeyResponse.nonceKey33

        // log how many nonces we have and we need
        val noncesCount =
            session.participantsMids.count { sessionsPrivate[session.id]!!.participants[it]!!.nonceKey33 != null }
        val noncesNeeded = session.participantsMids.size
        log("Received nonce from ${peer.mid}, nonces count: $noncesCount, needed: $noncesNeeded")

        val allNoncesReceived = session.participantsMids.all {
            sessionsPrivate[session.id]!!.participants[it]!!.nonceKey33 != null
        }

        // if we have a partial signature request waiting, send it now
        if (partialSignatureRequestsWaiting[Pair(session.id, peer.mid)] != null) {
            onReceivePartialSignatureRequest(
                partialSignatureRequestsWaiting[
                    Pair(
                        session.id,
                        peer.mid
                    )
                ]!!
            )
        }

        tryAndRequestNonces(nonceKeyResponse.sessionId)

        if (allNoncesReceived) {
            log("All nonces received, requesting partial signatures")
            requestPartialSignatures(nonceKeyResponse.sessionId)
        }
    }

    private fun requestPartialSignatures(sessionId: String) {
        val session = getSession(sessionId)!!

        // get all mids for which we have no partial signature
        val mids = session.participantsMids.filter {
            sessionsPrivate[session.id]!!.participants[it]!!.partialSignature == null
        }
        val outstandingMids = session.participantsMids.filter {
            outstandingCache[
                Pair(
                    session.id,
                    it
                )
            ]?.contains(ON_RECEIVE_PARTIAL_SIGNATURE_REQUEST) == true
        }
        val midsToRequest = mids.filter { !outstandingMids.contains(it) }

        val partialSignatureCount = session.participantsMids.count {
            sessionsPrivate[session.id]!!.participants[it]!!.partialSignature != null
        }
        val partialSignatureNeeded = session.participantsMids.size

        log(
            "requestPartialSignatures: partialSignatureCount: $partialSignatureCount/$partialSignatureNeeded, mids: ${mids.size}, outstandindMids: ${outstandingMids.size}, midsToRequest: ${midsToRequest.size})\n"
        )

        midsToRequest.forEach { mid ->
            val peer = findPeer(mid)
            if (peer != null) {
                val packet =
                    serializePacket(ON_PARTIAL_SIGNATURE_REQUEST, StringMessage(session.id))
                log("Sending partial signature request to $mid")
                send(peer, packet)

                // add ACK waiting for partial signature from peer
                outstandingCache.getOrPut(Pair(session.id, peer.mid)) { mutableSetOf() }
                    .add(ON_RECEIVE_PARTIAL_SIGNATURE_REQUEST)
            }
        }
    }

    private fun onReceivePartialSignatureRequest(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(StringMessage.Deserializer)
        val sessionId = payload.message

        val session = getSession(sessionId)!!

        val noncesCount =
            session.participantsMids.count { sessionsPrivate[session.id]!!.participants[it]!!.nonceKey33 != null }
        val noncesNeeded = session.participantsMids.size
        val publicKeysCount =
            session.participantsMids.count { sessionsPrivate[session.id]!!.participants[it]!!.publicKey33 != null }
        val publicKeysNeeded = session.participantsMids.size
        log("Received partial signature request from ${peer.mid}, nonces count: $noncesCount/$noncesNeeded, public keys count: $publicKeysCount/$publicKeysNeeded")

        // start creating partial signature
        val allPublicKeys =
            session.participantsMids.all { sessionsPrivate[session.id]!!.participants[it]!!.publicKey33 != null }

        val allNonceKeys = session.participantsMids.all {
            sessionsPrivate[session.id]!!.participants[it]!!.nonceKey33 != null
        }

        if (!allPublicKeys) {
            log("Not all public keys received, cannot sign...")
            // save packet for later
            partialSignatureRequestsWaiting[Pair(session.id, peer.mid)] = packet
            return
        }

        if (!allNonceKeys) {
            log("Not all nonce keys received, cannot sign...")
            // save packet for later
            partialSignatureRequestsWaiting[Pair(session.id, peer.mid)] = packet
            return
        }

        val publicECKeys = session.participantsMids.map {
            val publicKeyBytes = sessionsPrivate[session.id]!!.participants[it]!!.publicKey33
            val publicKey = ECKey.fromPublicOnly(publicKeyBytes)
            publicKey
        }

        val publicNonceKeys = session.participantsMids.map {
            val nonceKeyBytes = sessionsPrivate[session.id]!!.participants[it]!!.nonceKey33
            val nonceKey = ECKey.fromPublicOnly(nonceKeyBytes)
            nonceKey
        }

        // Public Key Aggregation & key tweaking:
        val (aggregatedPublicKey, tweakingKeys, hasBeenNegated) =
            BIP0340MuSig.generateAggregatedPublicKey(publicECKeys.map { it.pubKeyPoint })

        val tweakingKeysMapped =
            tweakingKeys.mapKeys { it.key.rawXCoord.toBigInteger().toString(16) }
        val coefficient = BigInteger(
            1,
            tweakingKeysMapped[privateKey.pubKeyPoint.rawXCoord.toBigInteger().toString(16)]
        )

        val tweakedKey =
            ECKey.fromPrivate(privateKey.privKey.multiply(coefficient).mod(ECKey.CURVE.n))
        val tweakedPublicKey = if (hasBeenNegated) {
            val ecSpec: ECNamedCurveParameterSpec =
                ECNamedCurveTable.getParameterSpec("secp256k1")
            val newSecKey = ecSpec.n.minus(tweakedKey.privKey).mod(ECKey.CURVE.n)
            ECKey.fromPrivate(newSecKey)
        } else {
            tweakedKey
        }

        // Nonce Aggregation & key tweaking:
        val nonce = nonces[sessionId]!!
        if (!nonces.containsKey(sessionId)) {
            log("No nonce found for session $sessionId")
            return
        }

        val (aggregatedNonce, nonceHasBeenNegated) = BIP0340MuSig.aggregateNonces(publicNonceKeys.map { it.pubKeyPoint })

        val tweakedNonceKey = if (nonceHasBeenNegated) {
            val ecSpec: ECNamedCurveParameterSpec =
                ECNamedCurveTable.getParameterSpec("secp256k1")
            val newSecKey = ecSpec.n.minus(nonce.privKey).mod(ECKey.CURVE.n)
            ECKey.fromPrivate(newSecKey)
        } else {
            nonce
        }

        // Partial signature creation:
        val message = session.message
        val partialSignature = bigIntegerToBytes(
            BIP0340MuSig.partialSign(
                publicKey = tweakedPublicKey,
                nonceKey = tweakedNonceKey,
                Pm = ECKey.fromPublicOnly(aggregatedPublicKey, true),
                Rm = ECKey.fromPublicOnly(aggregatedNonce, true),
                message = message
            ),
            64
        )

        // add partial signature to private session
        sessionsPrivate[session.id]!!.participants[myPeer.mid] =
            sessionsPrivate[session.id]!!.participants[myPeer.mid]!!.copy(
                partialSignature = partialSignature
            )

        // add aggregated keys to private session so we don't have to re-compute them
        sessionsPrivate[sessionId] = sessionsPrivate[sessionId]!!.copy(
            aggregatedPublicKey33 = aggregatedPublicKey.getEncoded(true),
            aggregatedNonce33 = aggregatedNonce.getEncoded(true)
        )

        val signatureResponse = PartialSignatureResponse(
            sessionId = sessionId,
            signature64 = partialSignature
        )

        // remove outstanding
        outstandingCache[Pair(session.id, peer.mid)]?.remove(ON_RECEIVE_PARTIAL_SIGNATURE_REQUEST)

        val json = Json.encodeToString(signatureResponse)
        val packet =
            serializePacket(ON_RECEIVE_PARTIAL_SIGNATURE_REQUEST, StringMessage(json))
        log("Sending partial signature response to ${peer.mid}")
        send(peer, packet)

        requestPartialSignatures(sessionId)
    }

    private fun onReceivePartialSignature(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(StringMessage.Deserializer)
        val partialSignatureResponse =
            Json.decodeFromString<PartialSignatureResponse>(payload.message)

        val session = getSession(partialSignatureResponse.sessionId)!!

        // stop if final signature already done
        if (sessionsPrivate[session.id]!!.finalSignature != null) {
            log("Final signature already done, ignoring partial signature request")
            return
        }

        // add received partial signature to private session
        sessionsPrivate[session.id]!!.participants[peer.mid] =
            sessionsPrivate[session.id]!!.participants[peer.mid]!!.copy(
                partialSignature = partialSignatureResponse.signature64
            )

        // log current partial signatures count/total
        val partialSignaturesCount = session.participantsMids.count { mid ->
            sessionsPrivate[session.id]!!.participants[mid]!!.partialSignature != null
        }
        log("Received $partialSignaturesCount/${session.participantsMids.size} partial signatures")

        val receivedAllPartialSignatures = session.participantsMids.all { mid ->
            sessionsPrivate[session.id]!!.participants[mid]!!.partialSignature != null
        }

        if (receivedAllPartialSignatures) {
            log("Received all partial signatures")

            val signatures = session.participantsMids.map { mid ->
                sessionsPrivate[session.id]!!.participants[mid]!!.partialSignature!!
            }.map { bytesToBigInteger(it) }
            val aggregatedNonce =
                ECKey.fromPublicOnly(sessionsPrivate[session.id]!!.aggregatedNonce33!!)

            val finalSignature =
                BIP0340MuSig.aggregateSignatures(signatures, aggregatedNonce.pubKeyPoint)
            log("Final signature: ${bytesToBigInteger(finalSignature).toString(16)}")

            // validate signature
            val pubkey32 = bigIntegerToBytes(
                ECKey.fromPublicOnly(sessionsPrivate[session.id]!!.aggregatedPublicKey33!!).pubKeyPoint.rawXCoord.toBigInteger(),
                32
            )

            val valid = BIP0340Schnorr.verify(
                session.message,
                pubkey32,
                finalSignature
            )
            log("Signature valid: $valid")

            // add final signature to private session
            sessionsPrivate[session.id] = sessionsPrivate[session.id]!!.copy(
                finalSignature = finalSignature
            )

            // call listeners (for performance evaluation / UI reasons)
            onSignatureFinished(valid)
        }

        requestPartialSignatures(session.id)
    }

    fun clearOnSignatureListeners() {
        signatureFinishedEventListeners.clear()
    }

    fun registerOnSignatureFinished(callback: (Boolean) -> Unit) {
        signatureFinishedEventListeners.add(callback)
    }

    private fun onSignatureFinished(valid: Boolean) {
        signatureFinishedEventListeners.forEach { it(valid) }
    }

    private fun findPeer(mid: String): Peer? {
        return network.verifiedPeers.find { it.mid == mid }
    }

    private fun getSession(id: String): Session? {
        return sessions[id]
    }

    private fun getSessionPrivate(id: String): SessionPrivate? {
        return sessionsPrivate[id]
    }

    private fun log(message: String) {
        Log.d("Experiments", "Node ${evaluationNode.id} (${myPeer.mid.take(3)}): $message")
    }

    class Factory(
        private val evaluationNode: EvaluationNode
    ) : Overlay.Factory<MultiSignatureCommunity>(MultiSignatureCommunity::class.java) {
        override fun create(): MultiSignatureCommunity {
            return MultiSignatureCommunity(evaluationNode)
        }
    }

    companion object {
        const val ON_REQUEST_PUBLIC_KEY = 1
        const val ON_RECEIVE_PUBLIC_KEY = 2
        const val ON_REQUEST_NONCE = 3
        const val ON_RECEIVE_NONCE = 4
        const val ON_PARTIAL_SIGNATURE_REQUEST = 5
        const val ON_RECEIVE_PARTIAL_SIGNATURE_REQUEST = 6
    }
}
