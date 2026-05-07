package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.LMOtsParameters;
import es.uma.nicslab.hbs.lms.LMSHashUtils;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.ByteUtils;

public class Aggregator {

    private final LMOtsParameters parameter;
    private final byte[] I;  // Identificador del árbol LMS

    public Aggregator(LMOtsParameters parameter, byte[] I) {
        this.parameter = parameter;
        this.I = I != null ? I.clone() : null;
    }

    public ThresholdSignature KK_Aggregator_Sign(byte[] message, byte[] keyID, CRV CRV, Trustee[] trustees) {

        int k = trustees.length;

        byte[][] sharesR = new byte[k][];
        byte[][] sharesCHK = new byte[k][];

        int i = 0;

        for (Trustee trustee : trustees) {
            Round1Msg round1 = trustee.KK_Sign1(keyID, message, CRV.getCHK().length);
            sharesR[i] = round1.getR_t();
            sharesCHK[i] = round1.getCHK_t();
            i++;
        }

        byte[] R = ByteUtils.xorAll(CRV.getR(), sharesR);
        byte[] CHKConcat = ByteUtils.xorAll(CRV.getCHK(), sharesCHK);

        byte[][] CHK = ByteUtils.deconcat(CHKConcat, k);

        byte[][] sharesPATH = new byte[k][];
        byte[][] sharesZ = new byte[k][];

        i = 0;

        for (Trustee trustee : trustees) {
            Round2Msg round2 = trustee.KK_Sign2(R, CHK[i], CRV.getPATH().length);
            sharesPATH[i] = round2.getPATH_t();
            sharesZ[i] = round2.getZ_t();
            i++;
        }

        byte[] PATHConcat = ByteUtils.xorAll(CRV.getPATH(), sharesPATH);

        byte[][] PATH = new byte[k][]; // ByteUtils.deconcat(PATHConcat, ); // TO DO --> HAY QUE BUSCAR EL TAMAÑO DEL PATH, O METERLO EN EL CRV O ALGO

        byte[] h = computeH(R, message, keyID);

        byte[] Z = new byte[32]; // TO DO

        return new ThresholdSignature(R, PATH, Z);
    }

    private byte[] computeH(byte[] R, byte[] M, byte[] keyID) {
        int q = ByteUtils.bytesToInt(keyID);
        return LMSHashUtils.computeH(parameter, I, q, R, M);
    }

}
