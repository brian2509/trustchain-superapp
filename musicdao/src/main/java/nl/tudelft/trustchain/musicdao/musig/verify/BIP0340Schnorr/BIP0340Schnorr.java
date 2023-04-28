package nl.tudelft.trustchain.musicdao.musig.verify.BIP0340Schnorr;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * https://github.com/SamouraiDev/BIP340_Schnorr/tree/master/src/com/samourai/wallet/schnorr
 */

public class BIP0340Schnorr {

    public static byte[] sign(byte[] msg, byte[] secKey, byte[] auxRand) throws Exception {
        if (msg.length != 32) {
            throw new Exception("The message must be a 32-byte array.");
        }
        BigInteger secKey0 = SchnorrUtil.bigIntFromBytes(secKey);

        if (!(BigInteger.ONE.compareTo(secKey0) <= 0 && secKey0.compareTo(SchnorrPoint.getn().subtract(BigInteger.ONE)) <= 0)) {
            throw new Exception("The secret key must be an integer in the range 1..n-1.");
        }
        SchnorrPoint P = SchnorrPoint.mul(SchnorrPoint.getG(), secKey0);
        if (!P.hasEvenY()) {
            secKey0 = SchnorrPoint.getn().subtract(secKey0);
        }
        int len = SchnorrUtil.bytesFromBigInteger(secKey0).length + P.toBytes().length + msg.length;
        byte[] buf = new byte[len];
        byte[] t = SchnorrUtil.xor(SchnorrUtil.bytesFromBigInteger(secKey0), SchnorrPoint.taggedHash("BIP0340/aux", auxRand));
        System.arraycopy(t, 0, buf, 0, t.length);
        System.arraycopy(P.toBytes(), 0, buf, t.length, P.toBytes().length);
        System.arraycopy(msg, 0, buf, t.length + P.toBytes().length, msg.length);
        BigInteger k0 = SchnorrUtil.bigIntFromBytes(SchnorrPoint.taggedHash("BIP0340/nonce", buf)).mod(SchnorrPoint.getn());
        if (k0.compareTo(BigInteger.ZERO) == 0) {
            throw new Exception("Failure. This happens only with negligible probability.");
        }
        SchnorrPoint R = SchnorrPoint.mul(SchnorrPoint.getG(), k0);
        BigInteger k = null;
        if (!R.hasEvenY()) {
            k = SchnorrPoint.getn().subtract(k0);
        } else {
            k = k0;
        }
        len = R.toBytes().length + P.toBytes().length + msg.length;
        buf = new byte[len];
        System.arraycopy(R.toBytes(), 0, buf, 0, R.toBytes().length);
        System.arraycopy(P.toBytes(), 0, buf, R.toBytes().length, P.toBytes().length);
        System.arraycopy(msg, 0, buf, R.toBytes().length + P.toBytes().length, msg.length);
        BigInteger e = SchnorrUtil.bigIntFromBytes(SchnorrPoint.taggedHash("BIP0340/challenge", buf)).mod(SchnorrPoint.getn());
        BigInteger kes = k.add(e.multiply(secKey0)).mod(SchnorrPoint.getn());
        len = R.toBytes().length + SchnorrUtil.bytesFromBigInteger(kes).length;
        byte[] sig = new byte[len];
        System.arraycopy(R.toBytes(), 0, sig, 0, R.toBytes().length);
        System.arraycopy(SchnorrUtil.bytesFromBigInteger(kes), 0, sig, R.toBytes().length, SchnorrUtil.bytesFromBigInteger(kes).length);
        if (!verify(msg, P.toBytes(), sig)) {
            throw new Exception("The signature does not pass verification.");
        }
        return sig;
    }

    public static boolean verify(byte[] msg, byte[] pubkey, byte[] sig) throws Exception {
        if (msg.length != 32) {
            throw new Exception("The message must be a 32-byte array.");
        }
        if (pubkey.length != 32) {
            throw new Exception("The public key must be a 32-byte array.");
        }
        if (sig.length != 64) {
            throw new Exception("The signature must be a 64-byte array.");
        }

        SchnorrPoint P = SchnorrPoint.liftX(pubkey);
        if (P == null) {
            return false;
        }
        BigInteger r = SchnorrUtil.bigIntFromBytes(Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = SchnorrUtil.bigIntFromBytes(Arrays.copyOfRange(sig, 32, 64));
        if (r.compareTo(SchnorrPoint.getp()) >= 0 || s.compareTo(SchnorrPoint.getn()) >= 0) {
            return false;
        }
        int len = 32 + pubkey.length + msg.length;
        byte[] buf = new byte[len];
        System.arraycopy(sig, 0, buf, 0, 32);
        System.arraycopy(pubkey, 0, buf, 32, pubkey.length);
        System.arraycopy(msg, 0, buf, 32 + pubkey.length, msg.length);
        byte[] hash = SchnorrPoint.taggedHash("BIP0340/challenge", buf);
        BigInteger e = SchnorrUtil.bigIntFromBytes(hash).mod(SchnorrPoint.getn());
        SchnorrPoint R = SchnorrPoint.add(SchnorrPoint.mul(SchnorrPoint.getG(), s), SchnorrPoint.mul(P, SchnorrPoint.getn().subtract(e)));
        if (R == null || !R.hasEvenY() || R.getX().compareTo(r) != 0) {
            return false;
        } else {
            return true;
        }
    }

}
