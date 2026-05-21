package es.uma.nicslab.hbs.lms;

import org.bouncycastle.crypto.Digest;

public class LMSHashUtils {

    private static final short D_MESG = (short) 0x8181;

    /**
     * Calcula h = H(I || u32str(q) || u16str(D_MESG) || R || message)
     */
    public static byte[] computeH(LMOtsParameters parameter, byte[] I, int q, byte[] R, byte[] message) {

        Digest digest = DigestUtil.getDigest(parameter);

        LmsUtils.byteArray(I, digest);
        LmsUtils.u32str(q, digest);
        LmsUtils.u16str(D_MESG, digest);
        LmsUtils.byteArray(R, digest);
        LmsUtils.byteArray(message, digest);

        byte[] h = new byte[digest.getDigestSize()];
        digest.doFinal(h, 0);

        return h;
    }
}