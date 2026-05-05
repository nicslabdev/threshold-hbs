package es.uma.nicslab.hbs.model;

public class Round1Msg {

    private final byte[] R_t;    // PRF^R_{K[t]}(KeyID, n)
    private final byte[] CHK_t;  // PRF^CHK_{K[t]}(KeyID, |CHK|)

    public Round1Msg(byte[] R_t, byte[] CHK_t) {
        this.R_t   = R_t   != null ? R_t.clone()   : null;
        this.CHK_t = CHK_t != null ? CHK_t.clone() : null;
    }

    public byte[] getR_t() {
        return R_t != null ? R_t.clone() : null;
    }

    public byte[] getChk_t() {
        return CHK_t != null ? CHK_t.clone() : null;
    }

}