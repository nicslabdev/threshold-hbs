package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.CASReader;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.protocol.TrusteeProxy;
import es.uma.nicslab.hbs.util.ByteUtils;

/**
 * Rol del Aggregator en el protocolo threshold HBS.
 *
 * Usa TrusteeProxy[] en lugar de Trustee[] para ser agnóstico sobre si
 * los trustees son locales (tests) o remotos via gRPC (producción).
 *
 * Las llamadas a trustees dentro de cada ronda son secuenciales.
 * callShardSign1 y callShardSign2 son puntos de extensión para migrar
 * a CompletableFuture en el futuro sin cambiar el flujo principal.
 */
public class Aggregator {

    private final LMSPublicKeyParameters lmsPublicKey;
    private final CASReader cas;
    private final String clCid;

    public Aggregator(LMSPublicKeyParameters lmsPublicKey, CASReader cas, String clCid) {
        this.lmsPublicKey = lmsPublicKey;
        this.cas = cas;
        this.clCid = clCid;
    }

    public ThresholdSignature aggregatorSign(byte[] message, int keyID, TrusteeProxy[] trustees) throws Exception {

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
            Round1Msg round1 = callShardSign1(trustees[C[i]], keyIdBytes, message);
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
            Round2Msg round2 = callShardSign2(trustees[C[i]], keyIdBytes, R, CHK[i]);
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

    public ThresholdSignature kkAggregatorSign(byte[] message, byte[] keyID, TrusteeProxy[] trustees) throws Exception {

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
            Round1Msg round1 = callShardSign1(trustees[i], keyID, message);
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
            Round2Msg round2 = callShardSign2(trustees[i], keyID, R, CHK[i]);
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

    // -------------------------------------------------------------------------
    // Puntos de extensión para paralelización futura con CompletableFuture
    // -------------------------------------------------------------------------

    private Round1Msg callShardSign1(TrusteeProxy trustee, byte[] keyID, byte[] message) throws Exception {
        return trustee.shardSign1(keyID, message);
    }

    private Round2Msg callShardSign2(TrusteeProxy trustee, byte[] keyID, byte[] R, byte[] chkI) throws Exception {
        return trustee.shardSign2(keyID, R, chkI);
    }

    private byte[] computeH(byte[] R, byte[] M, byte[] keyID) {
        int q = ByteUtils.bytesToInt(keyID);
        return LMSHashUtils.computeH(lmsPublicKey.getOtsParameters(), lmsPublicKey.getI(), q, R, M);
    }

}