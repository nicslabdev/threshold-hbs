package es.uma.nicslab.hbs.model;

public class Round2Request {

    private final byte[] R; // Randomizer reconstruido por el Aggregator
    private final byte[] CHK_t; // Porción del CHK reconstruido correspondiente al trustee t
    private final byte[] message; // Mensaje original M

    public Round2Request(byte[] R, byte[] CHK_t, byte[] message) {
        this.R = R != null ? R.clone() : null;
        this.CHK_t = CHK_t != null ? CHK_t.clone() : null;
        this.message = message != null ? message.clone() : null;
    }

    public byte[] getR() {
        return R != null ? R.clone() : null;
    }

    public byte[] getCHK_t() {
        return CHK_t != null ? CHK_t.clone() : null;
    }

    public byte[] getMessage() {
        return message != null ? message.clone() : null;
    }

}