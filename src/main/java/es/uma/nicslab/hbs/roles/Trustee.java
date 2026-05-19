package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.util.*;

import java.util.HashSet;
import java.util.Set;


public class Trustee {

    private final byte[] K; // clave secreta del trustee de la PRF
    private byte[] keyID;
    private byte[] current; // mensaje M entre Round 1 y Round 2 — null == None
    private final Set<String> usedKeyIDs = new HashSet<>();
    private final Set<Integer> keylist = new HashSet<>();
    private final PublicBulletinBoard board;

    public Trustee(byte[] K, PublicBulletinBoard board) {
        this.keyID = null;
        this.current = null;
        this.board = board;
        this.K = K != null ? K.clone() : null;
    }

    public void TrusteeSetup(int trusteeIndex, int[][] CL) {
        for (int keyID = 0; keyID < CL.length; keyID++) {
            for (int member : CL[keyID]) {
                if (member == trusteeIndex) {
                    keylist.add(keyID);
                    break;
                }
            }
        }
    }

    public Round1Msg ShardSign1(byte[] keyID, byte[] message) {

        int keyIDInt = ByteUtils.bytesToInt(keyID);

        if (!keylist.contains(keyIDInt)) {
            return null;
        }

        if (current != null) {
            return null;
        }

        keylist.remove(keyIDInt);
        this.keyID = keyID;
        this.current = message.clone();

        return KK_GenSig1();
    }

    public Round2Msg ShardSign2(byte[] R, byte[] CHK) {
        return KK_Sign2(R, CHK);
    }

    public Round1Msg KK_Sign1(byte[] keyID, byte[] message) {

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

        return KK_GenSig1();
    }

    private Round1Msg KK_GenSig1() {

        int n = board.getParameter().getN();

        byte[] R_t = PRF.evalR(K, keyID, n);
        byte[] CHK_t = PRF.evalCHK(K, keyID, board.getCRV(ByteUtils.bytesToInt(keyID)).getCHK().length);

        return new Round1Msg(R_t, CHK_t);
    }

    public Round2Msg KK_Sign2(byte[] R, byte[] CHK) {

        if (current == null) {
            return null;
        }

        byte[] M = current;
        current = null;

        if (!KK_Auth(R, CHK)) {
            return null;
        }

        byte[] h = computeH(R, M);

        return KK_GenSig2(h);
    }

    private boolean KK_Auth(byte[] R, byte[] CHK_t) {
        int n = board.getParameter().getN();
        byte[] expected = PRF.evalAUTH(K, keyID, R, n);
        return ByteUtils.constantTimeEquals(expected, CHK_t);
    }

    private Round2Msg KK_GenSig2(byte[] h) {

        int n = board.getParameter().getN();
        int chains = board.getParameter().getP();
        int steps = (1 << board.getParameter().getW()); // 2^w

        byte[][][] SK_t = new byte[chains][steps][];
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                SK_t[i][j] = PRF.evalCHAIN(K, keyID, i, j, n);
            }
        }

        byte[] Z_t = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, SK_t, board.getParameter());
        byte[] PATH_t = PRF.evalPATH(K, keyID, board.getCRV(ByteUtils.bytesToInt(keyID)).getPATH().length);

        keyID = null;

        return new Round2Msg(Z_t, PATH_t);
    }

    private byte[] computeH(byte[] R, byte[] M) {
        int q = ByteUtils.bytesToInt(keyID);
        return LMSHashUtils.computeH(board.getParameter(), board.getI(), q, R, M);
    }

}
