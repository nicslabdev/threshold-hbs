package es.uma.nicslab.hbs.lms;

public class LMOtsChain {

    private final LMOtsParameters parameter;
    private final byte[][][] SK;
    private final byte[] I;
    private final int q;

    LMOtsChain(LMOtsParameters parameter, byte[][][] SK, byte[] I, int q) {
        this.parameter = parameter;
        this.SK = SK;
        this.I = I;
        this.q = q;
    }

    public LMOtsParameters getParameter() {
        return parameter;
    }

    public byte[][][] getSK() {
        return SK;
    }

    public byte[] getI() {
        return I;
    }

    public int getQ() {
        return q;
    }

}
