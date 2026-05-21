package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.LMSPublicKeyParameters;
import es.uma.nicslab.hbs.model.CRV;
import es.uma.nicslab.hbs.roles.Trustee;

public class PublicBulletinBoard {

    private CRV[] CRV;
    private final LMSPublicKeyParameters publicKey;
    private Trustee[] trustees;
    private final int[][] CL;

    public PublicBulletinBoard(LMSPublicKeyParameters publicKey, int[][] CL) {
        this.publicKey = publicKey;
        this.CL = CL;
    }

    public void publishCRV(CRV[] CRV) {
        this.CRV = CRV;
    }

    public void publishTrustees(Trustee[] trustees) {
        this.trustees = trustees;
    }

    public CRV[] getCRV() {
        return CRV;
    }

    public CRV getCRV(int i) {
        return CRV[i];
    }

    public LMSPublicKeyParameters getPublicKey() {
        return publicKey;
    }

    public Trustee[] getTrustees() {
        return trustees;
    }

    public int[][] getCL() {
        return CL;
    }

}