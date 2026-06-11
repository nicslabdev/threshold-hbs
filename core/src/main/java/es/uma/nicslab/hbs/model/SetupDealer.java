package es.uma.nicslab.hbs.model;

import es.uma.nicslab.hbs.lms.LMSPublicKeyParameters;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;

public class SetupDealer {

    private final LMSPublicKeyParameters lmsPublicKey;
    private final CoalitionEntry[] cl;
    private final String clCid;
    private final byte[][] K;
    private final int lengthCHK;
    private final int lengthPath;

    public SetupDealer(LMSPublicKeyParameters lmsPublicKey, CoalitionEntry[] cl, String clCid, byte[][] K, int lengthCHK, int lengthPath) {
        this.lmsPublicKey = lmsPublicKey;
        this.cl = cl;
        this.clCid = clCid;
        this.K = K;
        this.lengthCHK = lengthCHK;
        this.lengthPath = lengthPath;
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

    public byte[][] getK() {
        return K;
    }

    public int getLengthCHK() {
        return lengthCHK;
    }

    public int getLengthPath() {
        return lengthPath;
    }

}