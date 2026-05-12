package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.LMOtsParameters;
import es.uma.nicslab.hbs.lms.LMOtsPublicKey;
import es.uma.nicslab.hbs.lms.LMSPublicKeyParameters;
import es.uma.nicslab.hbs.model.CRV;
import es.uma.nicslab.hbs.roles.Trustee;

public class PublicBulletinBoard {

    private CRV CRV;
    private final LMSPublicKeyParameters publicKey;
    private Trustee[] trustees;
    private final LMOtsParameters parameter;
    private final byte[] I;  // Identificador del árbol LMS

    public PublicBulletinBoard(LMSPublicKeyParameters publicKey, LMOtsParameters parameter, byte[] I) {
        this.publicKey = publicKey;
        this.parameter = parameter;
        this.I = I != null ? I.clone() : null;
    }

    public void publishCRV(CRV CRV) {
        this.CRV = CRV;
    }

    public void publishTrustees(Trustee[] trustees) {
        this.trustees = trustees;
    }

    public CRV getCRV() {
        return CRV;
    }

    public LMSPublicKeyParameters getPublicKey() {
        return publicKey;
    }

    public Trustee[] getTrustees() {
        return trustees;
    }

    public LMOtsParameters getParameter() {
        return parameter;
    }

    public byte[] getI() {
        return I;
    }

}