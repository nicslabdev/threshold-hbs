package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.*;

import java.util.HashSet;
import java.util.Set;


public class Trustee {

    private final TrusteeShare share; // K[t], keyId, parameter, I
    private byte[] current; // mensaje M entre Round 1 y Round 2 — null == None
    private final Set<String> usedKeyIds = new HashSet<>();

    public Trustee(TrusteeShare share) {
        this.share = share;
        this.current = null;
    }

    public Round1Msg KK_Sign1(byte[] keyID, byte[] message, int CHKLength) {

        if (current != null) {
            return null; // ⊥ — ya hay una firma en curso
        }
        if (!ByteUtils.constantTimeEquals(keyID, share.getKeyId())) {
            return null; // ⊥ — keyID no corresponde al asignado en el setup
        }
        // Comprobar si el keyID ya fue usado
        String keyIdHex = ByteUtils.toHex(keyID);
        if (usedKeyIds.contains(keyIdHex)) {
            return null; // ⊥ — keyID ya usado, one-time no permite reutilización
        }

        usedKeyIds.add(keyIdHex);
        current = message.clone();

        return KK_GenSig1(CHKLength);
    }

    private Round1Msg KK_GenSig1(int CHKLength) {

        int n = share.getParameter().getN();

        byte[] R_t = PRF.evalR(share.getK(), share.getKeyId(), n);
        byte[] CHK_t = PRF.evalCHK(share.getK(), share.getKeyId(), CHKLength);

        return new Round1Msg(R_t, CHK_t);
    }

    public Round2Msg KK_Sign2(byte[] R, byte[] CHK, int pathLength) {

        if (current == null) {
            return null;
        }

        byte[] M = current;
        current = null;

        if (!KK_Auth(R, CHK)) {
            return null;
        }

        byte[] h = computeH(R, M);

        return KK_GenSig2(h, pathLength);
    }

    private boolean KK_Auth(byte[] R, byte[] CHK_t) {
        int n = share.getParameter().getN();
        byte[] expected = PRF.evalAUTH(share.getK(), share.getKeyId(), R, n);
        return ByteUtils.constantTimeEquals(expected, CHK_t);
    }

    private Round2Msg KK_GenSig2(byte[] h, int pathLength) {

        LMOtsParameters parameter = share.getParameter();
        int n = parameter.getN();
        int chains = parameter.getP();
        int steps = (1 << parameter.getW()); // 2^w

        byte[][][] SK_t = new byte[chains][steps][];
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                SK_t[i][j] = PRF.evalCHAIN(share.getK(), share.getKeyId(), i, j, n);
            }
        }

        byte[] Z_t = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, SK_t, parameter);
        byte[] PATH_t = PRF.evalPATH(share.getK(), share.getKeyId(), pathLength);

        return new Round2Msg(Z_t, PATH_t);
    }

    private byte[] computeH(byte[] R, byte[] M) {
        int q = ByteUtils.bytesToInt(share.getKeyId());
        return LMSHashUtils.computeH(share.getParameter(), share.getI(), q, R, M);
    }

}
