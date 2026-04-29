package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.*;


public class Dealer {

    public static SetupResult KK_Setup(byte[][] keys, int keyId, byte[][][] SK, byte[] R, byte[][] PATH) {

        int k = keys.length;
        int n = R.length;
        byte[] keyIdBytes = ByteUtils.intToBytes(keyId);

        byte[][] CHK = new byte[k][];
        for (int t = 0; t < k; t++) {
            CHK[t] = PRF.evalAUTH(keys[t], keyIdBytes, R, n);
        }

        byte[][] sharesR    = new byte[k][];
        byte[][] sharesCHK  = new byte[k][];
        byte[][][] sharesPATH = new byte[k][][];
        byte[][][][] sharesSK = new byte[k][][][];

        for (int t = 0; t < k; t++) {
            // R_t = PRF^R_{K[t]}(KeyID, n)
            sharesR[t] = PRF.evalR(keys[t], keyIdBytes, n);

            // CHK_t ← PRF^CHK_{K[t]}(KeyID, |chk|)
            sharesCHK[t] = PRF.evalCHK(keys[t], keyIdBytes, n);

            // PATH_t ← PRF^PATH_{K[t]}(KeyID, |PATH|)
            sharesPATH[t] = new byte[PATH.length][];
            for (int i = 0; i < PATH.length; i++) {
                sharesPATH[t][i] = PRF.evalPATH(keys[t], keyIdBytes, PATH[i].length);
            }

            // SK_t[i][j] ← PRF^Chain_{K[t]}(KeyID, i, j, n)
            int chains = SK.length;
            int steps  = SK[0].length;
            sharesSK[t] = new byte[chains][steps][];
            for (int i = 0; i < chains; i++) {
                for (int j = 0; j < steps; j++) {
                    sharesSK[t][i][j] = PRF.evalCHAIN(keys[t], keyIdBytes, i, j, n);
                }
            }
        }

        // CRV.R = R ⊕ R_1 ⊕ ... ⊕ R_k
        byte[] crvR = ByteUtils.xorAll(R, sharesR);

        // CRV.CHK = CHK ⊕ CHK_1 ⊕ ... ⊕ CHK_k
        byte[] crvCHK = null; // OBTENER ESTO --> CREO QUE HAY QUE CAMBIAR CRV.CHK POR BYTE[][]

        // CRV.PATH = PATH ⊕ PATH_1 ⊕ ... ⊕ PATH_k
        byte[][] crvPATH = ByteUtils.xorPath(PATH, sharesPATH);

        // CRV.SK[i][j] = SK[i][j] ⊕ SK_1[i][j] ⊕ ... ⊕ SK_k[i][j]
        byte[][][] crvSK = ByteUtils.xorSK(SK, sharesSK);

        CRV crv = new CRV(crvR, crvCHK, crvPATH, crvSK);

        TrusteeShare[] shares = new TrusteeShare[k];
        for (int t = 0; t < k; t++) {
            shares[t] = new TrusteeShare(keyIdBytes, keys[t]);
        }

        return new SetupResult(crv, shares);
    }

}
