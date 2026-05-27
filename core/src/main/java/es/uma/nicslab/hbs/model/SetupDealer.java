package es.uma.nicslab.hbs.model;

import es.uma.nicslab.hbs.lms.LMSPublicKeyParameters;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.roles.Trustee;

/**
 * Resultado del Setup del Dealer.
 *
 * Contiene todo lo necesario para que el sistema pueda operar:
 *  - trustees:    array de Trustees configurados con sus claves PRF.
 *  - lmsPublicKey: clave pública LMS del esquema.
 *  - cl:          Coalition List con trustees y CID del CRV por KeyID.
 *  - clCid:       CID de la CL publicada en el CAS.
 */
public class SetupDealer {

    private final Trustee[] trustees;
    private final LMSPublicKeyParameters lmsPublicKey;
    private final CoalitionEntry[] cl;
    private final String clCid;

    public SetupDealer(Trustee[] trustees, LMSPublicKeyParameters lmsPublicKey, CoalitionEntry[] cl, String clCid) {
        this.trustees = trustees;
        this.lmsPublicKey = lmsPublicKey;
        this.cl = cl;
        this.clCid = clCid;
    }

    public Trustee[] getTrustees() {
        return trustees;
    }

    public LMSPublicKeyParameters getLmsPublicKey() {
        return lmsPublicKey;
    }

    public CoalitionEntry[] getCl() {
        return cl;
    }

    public String getClCid() {
        return clCid;
    }
}