package es.uma.nicslab.hbs.model;

import es.uma.nicslab.hbs.lms.LMOtsParameters;

public class TrusteeShare {

    private final byte[] keyId;
    private final byte[] K;
    private final LMOtsParameters parameter;

    public TrusteeShare(byte[] keyId, byte[] K, LMOtsParameters parameter) {
        this.keyId = keyId != null ? keyId.clone() : null;
        this.K = K != null ? K.clone() : null;
        this.parameter = parameter;
    }

    public byte[] getKeyId() {
        return keyId != null ? keyId.clone() : null;
    }

    public byte[] getK() {
        return K != null ? K.clone() : null;
    }

    public LMOtsParameters getParameter() {
        return parameter;
    }

}
