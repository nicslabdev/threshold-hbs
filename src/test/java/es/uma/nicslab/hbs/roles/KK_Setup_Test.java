package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.*;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class KK_Setup_Test {

    private byte[] R;
    private byte[][] PATH;
    private byte[][][] SK;
    private byte[][] keys;
    private int keyId;
    private int n;
    private int k;
    private byte[] keyIdBytes;
    private SetupResult result;

    @BeforeEach
    void setup() throws Exception {

        SecureRandom rng = new SecureRandom();
        k = 2;
        keyId = 0;
        keyIdBytes = ByteUtils.intToBytes(keyId);

        // Generar claves PRF de los trustees
        keys = new byte[k][32];
        for (int t = 0; t < k; t++) {
            rng.nextBytes(keys[t]);
        }

        // Generar par de claves LMS
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                rng
        );
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
        LMSPrivateKeyParameters lmsPrivate = (LMSPrivateKeyParameters) keyPair.getPrivate();

        // Obtener clave OTS y generar cadena SK completa
        LMOtsPrivateKey otsPrivateKey = lmsPrivate.getCurrentOTSKey();
        n = otsPrivateKey.getParameter().getN();

        LMSContext context = lmsPrivate.generateLMSContext();
        PATH = context.getPath();

        LMOtsChain chain = LM_OTS_WITH_CHAIN.lms_ots_generateChain(otsPrivateKey);
        SK = chain.getSK();
        LMOtsParameters parameter = chain.getParameter();

        // Randomizer
        R = new byte[n];
        rng.nextBytes(R);

        // Ejecutar KK_Setup
        result = Dealer.KK_Setup(keys, keyId, SK, R, PATH, parameter);

        CRV CRV = result.getCRV();

        System.out.println(CRV.toString());
    }

    @Test
    void testRReconstructed() {
        // sharesR[t] = PRF^R_{K[t]}(KeyID, n)
        byte[][] sharesR = new byte[k][];
        for (int t = 0; t < k; t++) {
            sharesR[t] = PRF.evalR(keys[t], keyIdBytes, n);
        }

        // CRV.R ⊕ sharesR[0] ⊕ ... ⊕ sharesR[k-1] == R original
        byte[] reconstructed = ByteUtils.xorAll(result.getCRV().getR(), sharesR);
        assertArrayEquals(R, reconstructed, "R no se reconstruye correctamente");
    }

    @Test
    void testCHKReconstructed() {
        // CHK[t] = PRF^Auth_{K[t]}(KeyID, R, n)
        byte[][] CHK = new byte[k][];
        for (int t = 0; t < k; t++) {
            CHK[t] = PRF.evalAUTH(keys[t], keyIdBytes, R, n);
        }
        byte[] CHKconcat = ByteUtils.concat(CHK);

        // sharesCHK[t] = PRF^CHK_{K[t]}(KeyID, |CHKconcat|)
        byte[][] sharesCHK = new byte[k][];
        for (int t = 0; t < k; t++) {
            sharesCHK[t] = PRF.evalCHK(keys[t], keyIdBytes, CHKconcat.length);
        }

        // CRV.CHK ⊕ sharesCHK[0] ⊕ ... ⊕ sharesCHK[k-1] == CHKconcat original
        byte[] reconstructed = ByteUtils.xorAll(result.getCRV().getCHK(), sharesCHK);
        assertArrayEquals(CHKconcat, reconstructed, "CHK no se reconstruye correctamente");
    }

    @Test
    void testPATHReconstructed() {
        byte[] PATHconcat = ByteUtils.concat(PATH);

        // sharesPATH[t] = PRF^PATH_{K[t]}(KeyID, |PATHconcat|)
        byte[][] sharesPATH = new byte[k][];
        for (int t = 0; t < k; t++) {
            sharesPATH[t] = PRF.evalPATH(keys[t], keyIdBytes, PATHconcat.length);
        }

        // CRV.PATH ⊕ sharesPATH[0] ⊕ ... ⊕ sharesPATH[k-1] == PATHconcat original
        byte[] reconstructed = ByteUtils.xorAll(result.getCRV().getPATH(), sharesPATH);
        assertArrayEquals(PATHconcat, reconstructed, "PATH no se reconstruye correctamente");
    }

    @Test
    void testSKReconstructed() {
        int chains = SK.length;
        int steps  = SK[0].length;

        // sharesSK[t][i][j] = PRF^Chain_{K[t]}(KeyID, i, j, n)
        byte[][][][] sharesSK = new byte[k][chains][steps][];
        for (int t = 0; t < k; t++) {
            for (int i = 0; i < chains; i++) {
                for (int j = 0; j < steps; j++) {
                    sharesSK[t][i][j] = PRF.evalCHAIN(keys[t], keyIdBytes, i, j, n);
                }
            }
        }

        // Para cada (i,j): CRV.SK[i][j] ⊕ sharesSK[0][i][j] ⊕ ... ⊕ sharesSK[k-1][i][j] == SK[i][j] original
        byte[][][] crvSK = result.getCRV().getSK();
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                byte[] reconstructed = crvSK[i][j].clone();
                for (int t = 0; t < k; t++) {
                    reconstructed = ByteUtils.xorBytes(reconstructed, sharesSK[t][i][j]);
                }
                assertArrayEquals(SK[i][j], reconstructed,
                        "SK[" + i + "][" + j + "] no se reconstruye correctamente");
            }
        }
    }

    @Test
    void testTrusteeSharesCount() {
        assertEquals(k, result.getShares().length, "Número de shares incorrecto");
    }

    @Test
    void testTrusteeShareKeyId() {
        for (TrusteeShare share : result.getShares()) {
            assertArrayEquals(keyIdBytes, share.getKeyId(), "KeyID incorrecto en TrusteeShare");
        }
    }
}