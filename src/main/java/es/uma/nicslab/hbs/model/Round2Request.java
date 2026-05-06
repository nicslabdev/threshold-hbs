package es.uma.nicslab.hbs.model;

public class Round2Request {

    private final byte[] R; // Randomizer reconstruido por el Aggregator
    private final byte[] CHK_t; // Porción del CHK reconstruido correspondiente al trustee t

    public Round2Request(byte[] R, byte[] CHK_t) {
        this.R = R != null ? R.clone() : null;
        this.CHK_t = CHK_t != null ? CHK_t.clone() : null;
    }

    public byte[] getR() {
        return R != null ? R.clone() : null;
    }

    public byte[] getCHK_t() {
        return CHK_t != null ? CHK_t.clone() : null;
    }

}