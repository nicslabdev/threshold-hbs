package es.uma.nicslab.hbs.model;

import es.uma.nicslab.hbs.lms.LMOtsParameters;

public class TrusteeShare {

    private final byte[] keyId;
    private final byte[] K;
    private final LMOtsParameters parameter;
    private final byte[] I;  // Identificador del árbol LMS

    public TrusteeShare(byte[] keyId, byte[] K, LMOtsParameters parameter, byte[] I) {
        this.keyId = keyId != null ? keyId.clone() : null;
        this.K = K != null ? K.clone() : null;
        this.parameter = parameter;
        this.I = I != null ? I.clone() : null;
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

    public byte[] getI() {
        return I != null ? I.clone() : null;
    }

}
