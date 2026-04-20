package es.uma.nicslab.hbs.lms;

public class LMOtsChain {

    private final LMOtsParameters parameter;
    private final byte[][][] sk;

    LMOtsChain(LMOtsParameters parameter, byte[][][] sk) {
        this.parameter = parameter;
        this.sk = sk;
    }

    public LMOtsParameters getParameter() {
        return parameter;
    }

    public byte[][][] getSk() {
        return sk;
    }

}
