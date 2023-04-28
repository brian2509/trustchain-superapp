package com.example.musicdao

import nl.tudelft.trustchain.musicdao.musig.verify.BIP0340Schnorr.BIP0340Schnorr
import nl.tudelft.trustchain.musicdao.experiments.verifySchnorrTaprootWorkshop
import nl.tudelft.trustchain.musicdao.musig.bigIntegerToBytes
import nl.tudelft.trustchain.musicdao.musig.bytesToBigInteger
import org.bitcoinj.core.ECKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test
import java.math.BigInteger
import java.security.Security

/**
 * https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
 */
class BIP0340SchnorrTest {
    @Test
    fun verifyTest() {
        Security.addProvider(BouncyCastleProvider())
        val publicKey32 = bigIntegerToBytes(
            BigInteger(
                "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                16
            ),
            32
        )

        val ecKey = ECKey.fromPrivate(
            BigInteger(
                "0000000000000000000000000000000000000000000000000000000000000003",
                16
            )
        )
        val message = bigIntegerToBytes(
            BigInteger(
                "0000000000000000000000000000000000000000000000000000000000000000",
                16
            ),
            32
        )
        val signature = bigIntegerToBytes(
            BigInteger(
                "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
                16

            ),
            64
        )

        assert(ecKey.pubKeyPoint.rawXCoord.toBigInteger() == bytesToBigInteger(publicKey32))

        val valid = BIP0340Schnorr.verify(
            message,
            bigIntegerToBytes(ecKey.pubKeyPoint.rawXCoord.toBigInteger(), 32),
            signature
        )
        val valid2 = verifySchnorrTaprootWorkshop(ecKey.pubKeyPoint, signature, message)
        assert(valid2)
        assert(valid)
    }
}
