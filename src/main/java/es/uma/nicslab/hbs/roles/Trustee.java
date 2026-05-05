package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.*;


public class Trustee {

    private final TrusteeShare share; // K[t], keyId, parameter
    private byte[] current; // mensaje M entre Round 1 y Round 2 — null == None

    public Trustee(TrusteeShare share) {
        this.share   = share;
        this.current = null;
    }

    public Round1Msg KK_Sign1(byte[] keyID, byte[] message, int CHKLength) {

        if (current != null) {
            return null; // ⊥ — ya hay una firma en curso
        }
        if (!ByteUtils.constantTimeEquals(keyID, share.getKeyId())) {
            return null; // ⊥ — keyID no corresponde al asignado en el setup
        }

        current = message.clone();

        return KK_GenSig1(CHKLength);
    }

    private Round1Msg KK_GenSig1(int CHKLength) {

        int n = share.getParameter().getN();

        byte[] R_t = PRF.evalR(share.getK(), share.getKeyId(), n);

        byte[] CHK_t = PRF.evalCHK(share.getK(), share.getKeyId(), CHKLength);

        return new Round1Msg(R_t, CHK_t);
    }

}
