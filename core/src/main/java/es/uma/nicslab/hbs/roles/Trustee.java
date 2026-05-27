package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.*;
import es.uma.nicslab.hbs.util.*;

/**
 * El estado operacional (keyList, signing state) se delega en
 * TrusteeStateStore, que puede ser en memoria (tests) o SQLite (producción).
 *
 * Los parámetros del esquema (K, lmotsParameters, I, lengthCHK, lengthPath)
 * se fijan en Setup y no cambian durante la vida del trustee.
 */
public class Trustee {

    private final byte[] K; // clave PRF secreta
    private final LMOtsParameters lmotsParameters; // parámetros LM-OTS
    private final byte[] I; // identificador árbol Merkle
    private final int lengthCHK; // longitud CHK concatenado
    private final int lengthPath; // longitud PATH concatenado

    private final TrusteeState store; // contiene el keyID y el mensaje actual

    /**
     * @param K                Clave PRF secreta de este trustee (32 bytes).
     * @param lmotsParameters  Parámetros LM-OTS del esquema.
     * @param I                Identificador del árbol Merkle (16 bytes).
     * @param lengthCHK        Longitud del CHK concatenado.
     * @param lengthPath       Longitud del PATH concatenado.
     * @param store            Almacén del estado operacional.
     */
    public Trustee(byte[] K, LMOtsParameters lmotsParameters, byte[] I, int lengthCHK, int lengthPath, TrusteeState store) {
        this.K = K != null ? K.clone() : null;
        this.lmotsParameters = lmotsParameters;
        this.I = I != null ? I.clone() : null;
        this.lengthCHK = lengthCHK;
        this.lengthPath = lengthPath;
        this.store = store;
    }

    /**
     * Inicializa la keyList con los KeyIDs que pertenecen a este trustee.
     * Se llama una vez tras el constructor, cuando el Dealer distribuye la CL.
     *
     * @param trusteeIndex Índice de este trustee en la coalición.
     * @param cl           Coalition List completa.
     */
    public void setup(int trusteeIndex, CoalitionEntry[] cl) throws Exception{
        int count = 0;
        for (CoalitionEntry entry : cl) {
            for (int member : entry.trustees()) {
                if (member == trusteeIndex) {
                    count++;
                    break;
                }
            }
        }

        int[] keyIDs = new int[count];
        int idx = 0;
        for (int keyID = 0; keyID < cl.length; keyID++) {
            for (int member : cl[keyID].trustees()) {
                if (member == trusteeIndex) {
                    keyIDs[idx++] = keyID;
                    break;
                }
            }
        }

        store.initKeyList(keyIDs);
    }


    /**
     * Round 1 del protocolo Shard.
     * Verifica que el KeyID pertenece a este trustee y no hay firma en curso.
     */
    public Round1Msg shardSign1(byte[] keyID, byte[] message) throws Exception {
        int keyIDInt = ByteUtils.bytesToInt(keyID);

        if (!store.claimKeyID(keyIDInt)) {
            return null; // ⊥ — KeyID no disponible o ya usado
        }

        if (store.hasSigningState()) {
            return null; // ⊥ — ya hay una firma en curso
        }

        store.saveSigningState(keyID, message);
        return KK_GenSig1(keyID);
    }

    /**
     * Round 2 del protocolo Shard. Delega en KK_Sign2.
     */
    public Round2Msg shardSign2(byte[] R, byte[] CHK) throws Exception{
        return KK_Sign2(R, CHK);
    }


    /**
     * Round 1 del protocolo k-of-k.
     */
    public Round1Msg kkSign1(byte[] keyID, byte[] message) throws Exception {
        if (store.hasSigningState()) {
            return null; // ⊥ — ya hay una firma en curso
        }

        int keyIDInt = ByteUtils.bytesToInt(keyID);
        if (!store.claimKeyID(keyIDInt)) {
            return null; // ⊥ — KeyID ya usado
        }

        store.saveSigningState(keyID, message);
        return KK_GenSig1(keyID);
    }

    /**
     * Round 2 del protocolo k-of-k.
     */
    public Round2Msg kkSign2(byte[] R, byte[] CHK) throws Exception {
        return KK_Sign2(R, CHK);
    }

    private Round1Msg KK_GenSig1(byte[] keyID) {
        byte[] R_t = PRF.evalR(K, keyID, lmotsParameters.getN());
        byte[] CHK_t = PRF.evalCHK(K, keyID, lengthCHK);
        return new Round1Msg(R_t, CHK_t);
    }

    private Round2Msg KK_Sign2(byte[] R, byte[] CHK) throws Exception{
        SigningState state = store.loadAndClearSigningState();
        if (state == null) {
            return null; // ⊥ — no hay firma en curso
        }

        byte[] keyID = state.keyID();
        byte[] M = state.message();

        if (!KK_Auth(R, CHK, keyID)) {
            return null; // ⊥ — verificación del randomizer fallida
        }

        byte[] h = computeH(R, M, keyID);
        return KK_GenSig2(h, keyID);
    }

    private boolean KK_Auth(byte[] R, byte[] CHK_t, byte[] keyID) {
        byte[] expected = PRF.evalAUTH(K, keyID, R, lmotsParameters.getN());
        return ByteUtils.constantTimeEquals(expected, CHK_t);
    }

    private Round2Msg KK_GenSig2(byte[] h, byte[] keyID) {
        int n = lmotsParameters.getN();
        int chains = lmotsParameters.getP();
        int steps = (1 << lmotsParameters.getW()); // 2^w

        byte[][][] SK_t = new byte[chains][steps][];
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                SK_t[i][j] = PRF.evalCHAIN(K, keyID, i, j, n);
            }
        }

        byte[] Z_t = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, SK_t, lmotsParameters);
        byte[] PATH_t = PRF.evalPATH(K, keyID, lengthPath);

        return new Round2Msg(Z_t, PATH_t);
    }

    private byte[] computeH(byte[] R, byte[] M, byte[] keyID) {
        int q = ByteUtils.bytesToInt(keyID);
        return LMSHashUtils.computeH(lmotsParameters, I, q, R, M);
    }

    public byte[] getK() {
        return K.clone();
    }

    public LMOtsParameters getLmotsParameters() {
        return lmotsParameters;
    }

    public byte[] getI() {
        return I.clone();
    }

    public int getLengthCHK() {
        return lengthCHK;
    }

    public int getLengthPath() {
        return lengthPath;
    }

}