package es.uma.nicslab.hbs.model;

public class Round2Msg {

    private final byte[] Z_t; // WINTER(h, SK_t) — p*n bytes
    private final byte[] PATH_t;  // PRF^PATH_{K[t]}(KeyID, |PATH|)

    public Round2Msg(byte[] Z_t, byte[] PATH_t) {
        this.Z_t    = Z_t    != null ? Z_t.clone()    : null;
        this.PATH_t = PATH_t != null ? PATH_t.clone() : null;
    }

    public byte[] getZ_t() {
        return Z_t != null ? Z_t.clone() : null;
    }

    public byte[] getPATH_t() {
        return PATH_t != null ? PATH_t.clone() : null;
    }

}