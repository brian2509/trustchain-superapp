package nl.tudelft.trustchain.musicdao.musig.verify.BIP0340Schnorr;

// clone of org.apache.commons.lang3.tuple.Pair;
/**
 * https://github.com/SamouraiDev/BIP340_Schnorr/tree/master/src/com/samourai/wallet/schnorr
 */

public class SchnorrPair<K, V> {

    private K elementLeft = null;
    private V elementRight = null;

    protected SchnorrPair() {
        ;
    }

    public static <K, V> SchnorrPair<K, V> of(K elementLeft, V elementRight) {
        return new SchnorrPair<K, V>(elementLeft, elementRight);
    }

    public SchnorrPair(K elementLeft, V elementRight) {
        this.elementLeft = elementLeft;
        this.elementRight = elementRight;
    }

    public K getLeft() {
        return elementLeft;
    }

    public V getRight() {
        return elementRight;
    }

    public boolean equals(SchnorrPair<K, V> p) {
        return (this.elementLeft.equals(p.getLeft())) && (this.elementRight.equals(p.getRight()));
    }

}
