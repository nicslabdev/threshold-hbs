package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.util.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.SecureRandom;

public class Dealer {

    private static final int PRF_KEY_LENGTH = 32;

    public SetupDealer ShardSetup(int k, int[][] CL, LMSParameters parameters) {

        SecureRandom rng = new SecureRandom();

        CRV[] crv = new CRV[CL.length];

        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(parameters, rng);
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        LMSPrivateKeyParameters lmsPrivate = (LMSPrivateKeyParameters) keyPair.getPrivate();
        LMSPublicKeyParameters lmsPublic = (LMSPublicKeyParameters) keyPair.getPublic();

        if (CL.length != lmsPrivate.getIndexLimit()) {
            throw new IllegalArgumentException(
                    "CL.length=" + CL.length + " must equal indexLimit=" + lmsPrivate.getIndexLimit()
            );
        }

        LMOtsParameters otsParameters = lmsPrivate.getOtsParameters();
        byte[] I = lmsPrivate.getI();

        PublicBulletinBoard board = new PublicBulletinBoard(lmsPublic, otsParameters, I, CL);

        byte[][] K = new byte[k][PRF_KEY_LENGTH];
        Trustee[] trustees = new Trustee[k];
        for (int i=0; i<k; i++) {
            rng.nextBytes(K[i]);
            trustees[i] = new Trustee(K[i], board);
        }
        board.publishTrustees(trustees);

        for (int keyID=0; keyID< lmsPrivate.getIndexLimit(); keyID++) {

            byte[] keyIdBytes = ByteUtils.intToBytes(keyID);

            if (lmsPrivate.getIndex() != keyID) {
                throw new IllegalStateException(
                        "LMS private key index mismatch: expected=" + keyID +
                        ", actual=" + lmsPrivate.getIndex());
            }

            LMOtsPrivateKey otsKey = lmsPrivate.getCurrentOTSKey();
            LMSContext context = lmsPrivate.generateLMSContext();

            byte[] R = context.getC();
            byte[][] PATH = context.getPath();
            LMOtsChain chain = LM_OTS_WITH_CHAIN.lms_ots_generateChain(otsKey);
            byte[][][] SK = chain.getSK();

            byte[][] keys = makeKeyList(K, CL[keyID]);

            crv[keyID] = KK_Setup(keys, keyIdBytes, SK, R, PATH);
        }

        board.publishCRV(crv);

        return new SetupDealer(trustees, board);
    }

    private CRV KK_Setup(byte[][] keys, byte[] keyID, byte[][][] SK, byte[] R, byte[][] PATH) {

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

        return new CRV(crvR, crvCHK, crvPATH, crvSK);
    }

    private static byte[][] makeKeyList(byte[][] K, int[] C) {
        byte[][] keylist = new byte[C.length][];
        for (int i = 0; i < C.length; i++) {
            if (C[i] < 0 || C[i] >= K.length) {
                throw new IllegalArgumentException("Coalition index C[" + i + "]=" + C[i] + " is out of bounds for K.length=" + K.length);
            }
            keylist[i] = K[C[i]].clone();
        }
        return keylist;
    }

}
