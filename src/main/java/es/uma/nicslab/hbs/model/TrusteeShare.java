package es.uma.nicslab.hbs.model;

public class TrusteeShare {

    private final byte[] keyId;
    private final byte[] K;

    public TrusteeShare(byte[] keyId, byte[] K) {
        this.keyId = keyId != null ? keyId.clone() : null;
        this.K = K != null ? K.clone() : null;
    }

    public byte[] getKeyId() {
        return keyId != null ? keyId.clone() : null;
    }

    public byte[] getK() {
        return K != null ? K.clone() : null;
    }

}
