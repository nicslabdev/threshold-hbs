package es.uma.nicslab.hbs.lms;

public class LMOtsChain {

    private final LMOtsParameters parameter;
    private final byte[][][] sk;
    private final byte[] I;
    private final int q;

    LMOtsChain(LMOtsParameters parameter, byte[][][] sk, byte[] I, int q) {
        this.parameter = parameter;
        this.sk = sk;
        this.I = I;
        this.q = q;
    }

    public LMOtsParameters getParameter() {
        return parameter;
    }

    public byte[][][] getSk() {
        return sk;
    }

    public byte[] getI() {
        return I;
    }

    public int getQ() {
        return q;
    }

}
