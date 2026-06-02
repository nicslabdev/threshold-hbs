package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.CASReader;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.util.ByteUtils;

import java.io.IOException;

/**
 * Rol del Aggregator en el protocolo threshold HBS.
 *
 * El Aggregator es una parte no confiable que coordina las dos rondas
 * de firma entre los trustees. Puede impedir que se generen firmas válidas
 * pero no puede forjarlas.
 *
 * Recibe la clave pública LMS y la CL del CAS, y se comunica con los
 * trustees para obtener sus shares de firma.
 */
public class Aggregator {

    private final LMSPublicKeyParameters lmsPublicKey;
    private final CASReader cas;
    private final String clCid;

    /**
     * @param lmsPublicKey Clave pública LMS del esquema.
     * @param cas          Lector del CAS para descargar CRVs y la CL.
     * @param clCid        CID de la Coalition List en el CAS.
     */
    public Aggregator(LMSPublicKeyParameters lmsPublicKey, CASReader cas, String clCid) {
        this.lmsPublicKey = lmsPublicKey;
        this.cas = cas;
        this.clCid = clCid;
    }

    /**
     * Genera una firma threshold para el mensaje dado usando el KeyID indicado.
     * Implementa el protocolo Shard (Algorithm 6 del paper).
     *
     * @param message Mensaje a firmar.
     * @param keyID   KeyID a usar (debe pertenecer a una coalición válida).
     * @return ThresholdSignature, o null si algún trustee rechazó participar.
     */
    public ThresholdSignature aggregatorSign(byte[] message, int keyID, Trustee[] trustees) throws Exception {

        CoalitionEntry[] cl = cas.getCL(clCid);
        CoalitionEntry entry = cl[keyID];
        int[] C = entry.trustees();
        int k = C.length;

        LMOtsParameters otsParams = lmsPublicKey.getOtsParameters();
        int n = otsParams.getN();
        byte[] keyIdBytes = ByteUtils.intToBytes(keyID);

        CRV crv = cas.getCRV(entry.crvCid());

        // --- Round 1 ---
        byte[][] sharesR = new byte[k][];
        byte[][] sharesCHK = new byte[k][];

        for (int i = 0; i < k; i++) {
            Round1Msg round1 = trustees[C[i]].shardSign1(keyIdBytes, message);
            if (round1 == null) return null;
            sharesR[i] = round1.getR_t();
            sharesCHK[i] = round1.getCHK_t();
        }

        byte[] R = ByteUtils.xorAll(crv.getR(), sharesR);
        byte[] CHKConcat = ByteUtils.xorAll(crv.getCHK(), sharesCHK);
        byte[][] CHK = ByteUtils.deconcat(CHKConcat, n);

        // --- Round 2 ---
        byte[][] sharesPATH = new byte[k][];
        byte[][] sharesZ = new byte[k][];

        for (int i = 0; i < k; i++) {
            Round2Msg round2 = trustees[C[i]].shardSign2(keyIdBytes, R, CHK[i]);
            if (round2 == null) return null;
            sharesPATH[i] = round2.getPATH_t();
            sharesZ[i] = round2.getZ_t();
        }

        byte[] PATHConcat = ByteUtils.xorAll(crv.getPATH(), sharesPATH);
        byte[][] PATH = ByteUtils.deconcat(PATHConcat, n);

        byte[] h = computeH(R, message, keyIdBytes);
        byte[] Z_CRV = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, crv.getSK(), otsParams);
        byte[] Z = ByteUtils.xorAll(Z_CRV, sharesZ);

        return new ThresholdSignature(R, PATH, Z);
    }

    /**
     * Genera una firma threshold k-of-k (todos los trustees participan).
     * Implementa KK_Aggregator_Sign (Algorithm 6 del paper).
     *
     * @param message Mensaje a firmar.
     * @param keyID   KeyID a usar.
     * @return ThresholdSignature, o null si algún trustee rechazó participar.
     */
    public ThresholdSignature kkAggregatorSign(byte[] message, byte[] keyID, Trustee[] trustees) throws Exception {

        CoalitionEntry[] cl = cas.getCL(clCid);
        int ID = ByteUtils.bytesToInt(keyID);
        CoalitionEntry entry = cl[ID];

        LMOtsParameters otsParams = lmsPublicKey.getOtsParameters();
        int n = otsParams.getN();
        int k = trustees.length;

        CRV crv = cas.getCRV(entry.crvCid());

        // --- Round 1 ---
        byte[][] sharesR = new byte[k][];
        byte[][] sharesCHK = new byte[k][];

        for (int i = 0; i < k; i++) {
            Round1Msg round1 = trustees[i].kkSign1(keyID, message);
            if (round1 == null) return null;
            sharesR[i] = round1.getR_t();
            sharesCHK[i] = round1.getCHK_t();
        }

        byte[] R = ByteUtils.xorAll(crv.getR(), sharesR);
        byte[] CHKConcat = ByteUtils.xorAll(crv.getCHK(), sharesCHK);
        byte[][] CHK = ByteUtils.deconcat(CHKConcat, n);

        // --- Round 2 ---
        byte[][] sharesPATH = new byte[k][];
        byte[][] sharesZ = new byte[k][];

        for (int i = 0; i < k; i++) {
            Round2Msg round2 = trustees[i].kkSign2(keyID, R, CHK[i]);
            if (round2 == null) return null;
            sharesPATH[i] = round2.getPATH_t();
            sharesZ[i] = round2.getZ_t();
        }

        byte[] PATHConcat = ByteUtils.xorAll(crv.getPATH(), sharesPATH);
        byte[][] PATH = ByteUtils.deconcat(PATHConcat, n);

        byte[] h = computeH(R, message, keyID);
        byte[] Z_CRV = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, crv.getSK(), otsParams);
        byte[] Z = ByteUtils.xorAll(Z_CRV, sharesZ);

        return new ThresholdSignature(R, PATH, Z);
    }

    private byte[] computeH(byte[] R, byte[] M, byte[] keyID) {
        int q = ByteUtils.bytesToInt(keyID);
        return LMSHashUtils.computeH(
                lmsPublicKey.getOtsParameters(),
                lmsPublicKey.getI(), q, R, M);
    }

}