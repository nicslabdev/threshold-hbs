package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.CASWriter;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.protocol.InMemoryTrusteeState;
import es.uma.nicslab.hbs.util.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * Rol del Dealer en el protocolo threshold HBS.
 *
 * Responsabilidades:
 *  1. Generar el keypair LMS.
 *  2. Para cada KeyID, generar el CRV y publicarlo en el CAS.
 *  3. Construir la Coalition List y publicarla en el CAS.
 *  4. Crear los Trustees con sus claves PRF y configurarlos.
 */
public class Dealer {

    private static final int PRF_KEY_LENGTH = 32;

    private final CASWriter cas;

    public Dealer(CASWriter cas) {
        this.cas = cas;
    }

    /**
     * Ejecuta el Setup completo del esquema threshold.
     *
     * @param k          Número de trustees.
     * @param coalitions Array de coaliciones: coalitions[keyID] = índices de trustees.
     * @param parameters Parámetros LMS para la generación del keypair.
     * @return SetupDealer con los trustees configurados, la clave pública,
     *         la CL y el CID de la CL en el CAS.
     */
    public SetupDealer setup(int k, int[][] coalitions, LMSParameters parameters) throws Exception {

        SecureRandom rng = new SecureRandom();

        // --- 1. Generar keypair LMS ---
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(parameters, rng);
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        LMSPrivateKeyParameters lmsPrivate = (LMSPrivateKeyParameters) keyPair.getPrivate();
        LMSPublicKeyParameters lmsPublic = (LMSPublicKeyParameters) keyPair.getPublic();

        int D = lmsPrivate.getIndexLimit();
        if (coalitions.length != D) {
            throw new IllegalArgumentException("coalitions.length=" + coalitions.length + " debe ser igual a indexLimit=" + D);
        }

        // --- 2. Generar claves PRF de los trustees ---
        byte[][] K = new byte[k][PRF_KEY_LENGTH];
        for (int i = 0; i < k; i++) {
            rng.nextBytes(K[i]);
        }

        // --- 3. Para cada KeyID: generar CRV y publicarlo en el CAS ---
        LMOtsParameters otsParams = lmsPublic.getOtsParameters();
        CoalitionEntry[] cl = new CoalitionEntry[D];

        // Calculamos lengthCHK y lengthPath a partir del primer CRV generado.
        // Son constantes para todos los KeyIDs con los mismos parámetros LM-OTS.
        int lengthCHK = -1;
        int lengthPath = -1;

        for (int keyID = 0; keyID < D; keyID++) {

            byte[] keyIdBytes = ByteUtils.intToBytes(keyID);

            if (lmsPrivate.getIndex() != keyID) {
                throw new IllegalStateException("LMS private key index mismatch: expected=" + keyID + ", actual=" + lmsPrivate.getIndex());
            }

            LMOtsPrivateKey otsKey = lmsPrivate.getCurrentOTSKey();
            LMSContext context = lmsPrivate.generateLMSContext();

            byte[] R = context.getC();
            byte[][] PATH = context.getPath();
            LMOtsChain chain = LM_OTS_WITH_CHAIN.lms_ots_generateChain(otsKey);
            byte[][][] SK = chain.getSK();

            byte[][] keys = makeKeyList(K, coalitions[keyID]);
            CRV crv = KK_Setup(keys, keyIdBytes, SK, R, PATH);

            if (lengthCHK == -1) {
                lengthCHK = crv.getCHK().length;
                lengthPath = crv.getPATH().length;
            }

            // Publicar el CRV en el CAS y obtener su CID
            String crvCid = cas.putCRV(keyID, crv);
            cl[keyID] = new CoalitionEntry(coalitions[keyID], crvCid);
        }

        // --- 4. Publicar la Coalition List en el CAS ---
        String clCid = cas.putCL(cl);

        // --- 5. Crear y configurar los trustees ---
        Trustee[] trustees = new Trustee[k];
        for (int i = 0; i < k; i++) {
            trustees[i] = new Trustee(K[i], otsParams, lmsPublic.getI(), lengthCHK, lengthPath, new InMemoryTrusteeState());
            trustees[i].setup(i, cl);
        }

        return new SetupDealer(trustees, lmsPublic, cl, clCid);
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

        int chains = SK.length;
        int steps = SK[0].length;

        for (int t = 0; t < k; t++) {
            sharesR[t] = PRF.evalR(keys[t], keyID, n);
            sharesCHK[t] = PRF.evalCHK(keys[t], keyID, CHKconcat.length);
            sharesPATH[t] = PRF.evalPATH(keys[t], keyID, PATHconcat.length);

            sharesSK[t] = new byte[chains][steps][];
            for (int i = 0; i < chains; i++) {
                for (int j = 0; j < steps; j++) {
                    sharesSK[t][i][j] = PRF.evalCHAIN(keys[t], keyID, i, j, n);
                }
            }
        }

        byte[] crvR = ByteUtils.xorAll(R, sharesR);
        byte[] crvCHK = ByteUtils.xorAll(CHKconcat, sharesCHK);
        byte[] crvPATH = ByteUtils.xorAll(PATHconcat, sharesPATH);
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