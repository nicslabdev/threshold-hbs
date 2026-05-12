package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.LMSHashUtils;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.util.ByteUtils;

public class Aggregator {

    private final PublicBulletinBoard board;

    public Aggregator(PublicBulletinBoard board) {
        this.board = board;
    }

    public ThresholdSignature KK_Aggregator_Sign(byte[] message, byte[] keyID) {

        int k = board.getTrustees().length;
        int n = board.getParameter().getN();

        byte[][] sharesR = new byte[k][];
        byte[][] sharesCHK = new byte[k][];

        int i = 0;

        for (Trustee trustee : board.getTrustees()) {
            Round1Msg round1 = trustee.KK_Sign1(keyID, message);
            if (round1 == null) return null; // ⊥ — algún trustee rechazó Round 1
            sharesR[i] = round1.getR_t();
            sharesCHK[i] = round1.getCHK_t();
            i++;
        }

        byte[] R = ByteUtils.xorAll(board.getCRV().getR(), sharesR);
        byte[] CHKConcat = ByteUtils.xorAll(board.getCRV().getCHK(), sharesCHK);

        byte[][] CHK = ByteUtils.deconcat(CHKConcat, n);

        byte[][] sharesPATH = new byte[k][];
        byte[][] sharesZ = new byte[k][];

        i = 0;

        for (Trustee trustee : board.getTrustees()) {
            Round2Msg round2 = trustee.KK_Sign2(R, CHK[i]);
            if (round2 == null) return null; // ⊥ — algún trustee rechazó Round 2
            sharesPATH[i] = round2.getPATH_t();
            sharesZ[i] = round2.getZ_t();
            i++;
        }

        byte[] PATHConcat = ByteUtils.xorAll(board.getCRV().getPATH(), sharesPATH);

        byte[][] PATH = ByteUtils.deconcat(PATHConcat, n);

        byte[] h = computeH(R, message, keyID);

        byte[] Z_CRV = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, board.getCRV().getSK(), board.getParameter());
        byte[] Z = ByteUtils.xorAll(Z_CRV, sharesZ);

        return new ThresholdSignature(R, PATH, Z);
    }

    private byte[] computeH(byte[] R, byte[] M, byte[] keyID) {
        int q = ByteUtils.bytesToInt(keyID);
        return LMSHashUtils.computeH(board.getParameter(), board.getI(), q, R, M);
    }

}
