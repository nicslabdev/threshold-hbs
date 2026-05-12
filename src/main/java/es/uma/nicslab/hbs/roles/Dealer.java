package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.util.*;

public class Dealer {

    private final PublicBulletinBoard board;

    public Dealer(PublicBulletinBoard board) {
        this.board = board;
    }

    public void KK_Setup(byte[][] keys, byte[] keyID, byte[][][] SK, byte[] R, byte[][] PATH) {

        int k = keys.length;
        int n = R.length;

        byte[][] CHK = new byte[k][];
        for (int t = 0; t < k; t++) {
            CHK[t] = PRF.evalAUTH(keys[t], keyID, R, n);
        }

        byte[] CHKconcat = ByteUtils.concat(CHK);
        byte[] PATHconcat = ByteUtils.concat(PATH);

        byte[][] sharesR = new byte[k][];
        byte[][] sharesCHK = new byte[k][];
        byte[][] sharesPATH = new byte[k][];
        byte[][][][] sharesSK = new byte[k][][][];

        for (int t = 0; t < k; t++) {
            // R_t = PRF^R_{K[t]}(KeyID, n)
            sharesR[t] = PRF.evalR(keys[t], keyID, n);

            // CHK_t ← PRF^CHK_{K[t]}(KeyID, |CHK|)
            sharesCHK[t] = PRF.evalCHK(keys[t], keyID, CHKconcat.length);

            // PATH_t ← PRF^PATH_{K[t]}(KeyID, |PATH|)
            sharesPATH[t] = PRF.evalPATH(keys[t], keyID, PATHconcat.length);

            // SK_t[i][j] ← PRF^CHAIN_{K[t]}(KeyID, i, j, n)
            int chains = SK.length;
            int steps  = SK[0].length;
            sharesSK[t] = new byte[chains][steps][];
            for (int i = 0; i < chains; i++) {
                for (int j = 0; j < steps; j++) {
                    sharesSK[t][i][j] = PRF.evalCHAIN(keys[t], keyID, i, j, n);
                }
            }
        }

        // CRV.R = R ⊕ R_1 ⊕ ... ⊕ R_k
        byte[] crvR = ByteUtils.xorAll(R, sharesR);

        // CRV.CHK = CHK ⊕ CHK_1 ⊕ ... ⊕ CHK_k
        byte[] crvCHK = ByteUtils.xorAll(CHKconcat, sharesCHK);

        // CRV.PATH = PATH ⊕ PATH_1 ⊕ ... ⊕ PATH_k
        byte[] crvPATH = ByteUtils.xorAll(PATHconcat, sharesPATH);

        // CRV.SK[i][j] = SK[i][j] ⊕ SK_1[i][j] ⊕ ... ⊕ SK_k[i][j]
        byte[][][] crvSK = ByteUtils.xorSK(SK, sharesSK);

        CRV crv = new CRV(crvR, crvCHK, crvPATH, crvSK);

        board.publishCRV(crv);
    }

}
