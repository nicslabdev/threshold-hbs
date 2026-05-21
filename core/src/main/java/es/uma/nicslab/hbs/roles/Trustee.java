package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.*;

import java.util.HashSet;
import java.util.Set;


public class Trustee {

    private final byte[] K; // clave secreta del trustee de la PRF
    private byte[] keyID;
    private byte[] current; // mensaje M entre Round 1 y Round 2 — null == None
    private final Set<String> usedKeyIDs = new HashSet<>();
    private final Set<Integer> keyList = new HashSet<>();

    public Trustee(byte[] K) {
        this.keyID = null;
        this.current = null;
        this.K = K != null ? K.clone() : null;
    }

    public void TrusteeSetup(int trusteeIndex, int[][] CL) {
        for (int keyID = 0; keyID < CL.length; keyID++) {
            for (int member : CL[keyID]) {
                if (member == trusteeIndex) {
                    keyList.add(keyID);
                    break;
                }
            }
        }
    }

    public Round1Msg ShardSign1(byte[] keyID, byte[] message, int n, int lengthCHK) {

        int keyIDInt = ByteUtils.bytesToInt(keyID);

        if (!keyList.contains(keyIDInt)) {
            return null;
        }

        if (current != null) {
            return null;
        }

        keyList.remove(keyIDInt);
        this.keyID = keyID;
        this.current = message.clone();

        return KK_GenSig1(n, lengthCHK);
    }

    public Round1Msg KK_Sign1(byte[] keyID, byte[] message, int n, int lengthCHK) {

        if (current != null) {
            return null; // ⊥ — ya hay una firma en curso
        }

        String keyIdHex = ByteUtils.toHex(keyID);
        if (usedKeyIDs.contains(keyIdHex)) {
            return null; // ⊥ — keyID ya usado, one-time no permite reutilización
        }

        this.keyID = keyID;

        usedKeyIDs.add(keyIdHex);
        current = message.clone();

        return KK_GenSig1(n, lengthCHK);
    }

    private Round1Msg KK_GenSig1(int n, int lengthCHK) {

        byte[] R_t = PRF.evalR(K, keyID, n);
        byte[] CHK_t = PRF.evalCHK(K, keyID, lengthCHK);

        return new Round1Msg(R_t, CHK_t);
    }

    public Round2Msg ShardSign2(byte[] R, byte[] CHK, LMOtsParameters parameters, int lengthPATH, byte[] I) {
        return KK_Sign2(R, CHK, parameters, lengthPATH, I);
    }

    public Round2Msg KK_Sign2(byte[] R, byte[] CHK, LMOtsParameters parameters, int lengthPATH, byte[] I) {

        if (current == null) {
            return null;
        }

        byte[] M = current;
        current = null;

        if (!KK_Auth(R, CHK, parameters.getN())) {
            return null;
        }

        byte[] h = computeH(R, M, parameters, I);

        return KK_GenSig2(h, parameters, lengthPATH);
    }

    private boolean KK_Auth(byte[] R, byte[] CHK_t, int n) {
        byte[] expected = PRF.evalAUTH(K, keyID, R, n);
        return ByteUtils.constantTimeEquals(expected, CHK_t);
    }

    private Round2Msg KK_GenSig2(byte[] h,LMOtsParameters parameters, int lengthPATH) {

        int n = parameters.getN();
        int chains = parameters.getP();
        int steps = (1 << parameters.getW()); // 2^w

        byte[][][] SK_t = new byte[chains][steps][];
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                SK_t[i][j] = PRF.evalCHAIN(K, keyID, i, j, n);
            }
        }

        byte[] Z_t = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, SK_t, parameters);
        byte[] PATH_t = PRF.evalPATH(K, keyID, lengthPATH);

        keyID = null;

        return new Round2Msg(Z_t, PATH_t);
    }

    private byte[] computeH(byte[] R, byte[] M, LMOtsParameters parameters, byte[] I) {
        int q = ByteUtils.bytesToInt(keyID);
        return LMSHashUtils.computeH(parameters, I, q, R, M);
    }

}
