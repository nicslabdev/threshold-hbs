package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class AggregatorTest {

    private Aggregator aggregator;
    private Trustee[] trustees;
    private CRV CRV;
    private byte[] keyIdBytes;
    private byte[] message;
    private byte[] R;
    private LMOtsParameters parameter;
    private int n;
    private int k;

    @BeforeEach
    void setup() throws Exception {

        SecureRandom rng = new SecureRandom();
        k = 2;

        // Par de claves LMS
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                rng
        );
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
        LMSPrivateKeyParameters lmsPrivate = (LMSPrivateKeyParameters) keyPair.getPrivate();

        parameter = lmsPrivate.getOtsParameters();
        byte[] I = lmsPrivate.getI();
        n = parameter.getN();
        keyIdBytes = ByteUtils.intToBytes(0);
        message = "mensaje de prueba".getBytes();

        // Randomizer
        R = new byte[n];
        rng.nextBytes(R);

        // Cadena SK y PATH
        LMOtsPrivateKey otsPrivateKey = lmsPrivate.getCurrentOTSKey();
        LMSContext context = lmsPrivate.generateLMSContext();
        byte[][] PATH = context.getPath();
        LMOtsChain chain = LM_OTS_WITH_CHAIN.lms_ots_generateChain(otsPrivateKey);
        byte[][][] SK = chain.getSK();

        // Claves PRF de los trustees
        byte[][] keys = new byte[k][32];
        for (int t = 0; t < k; t++) rng.nextBytes(keys[t]);

        // KK_Setup
        SetupResult result = Dealer.KK_Setup(keys, 0, SK, R, PATH);
        CRV = result.getCRV();

        // Construir trustees y cargar shares
        trustees = new Trustee[k];
        for (int t = 0; t < k; t++) {
            trustees[t] = new Trustee(parameter, I);
            trustees[t].loadShare(result.getShares()[t]);
        }

        // Aggregator
        aggregator = new Aggregator(parameter, I);
    }

    @Test
    void testFlujoCompletoDevuelveThresholdSignature() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes, CRV, trustees);
        assertNotNull(sig, "KK_Aggregator_Sign debe devolver ThresholdSignature");
    }

    @Test
    void testRTieneNBytes() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes, CRV, trustees);
        assertNotNull(sig);
        assertEquals(n, sig.getR().length, "R debe tener n bytes");
    }

    @Test
    void testZTienePNBytes() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes, CRV, trustees);
        assertNotNull(sig);
        assertEquals(parameter.getP() * n, sig.getZ().length, "Z debe tener p*n bytes");
    }

    @Test
    void testPATHTieneHNodos() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes, CRV, trustees);
        assertNotNull(sig);
        // h=5 nodos con lms_sha256_n32_h5
        assertEquals(5, sig.getPATH().length, "PATH debe tener h nodos");
        for (int i = 0; i < sig.getPATH().length; i++) {
            assertEquals(n, sig.getPATH()[i].length, "Nodo " + i + " del PATH debe tener n bytes");
        }
    }

    @Test
    void testRSeReconstruyeCorrectamente() {
        // R reconstruido = CRV.R ⊕ R_1 ⊕ R_2 == R original
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes, CRV, trustees);
        assertNotNull(sig);
        assertArrayEquals(R, sig.getR(), "R reconstruido debe coincidir con R original del dealer");
    }

    @Test
    void testDevuelveNullSiTrusteeSign1Falla() {
        // Trustee sin share cargado → KK_Sign1 devuelve null
        trustees[0] = new Trustee(parameter, CRV.getR()); // I incorrecto — share null
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes, CRV, trustees);
        assertNull(sig, "Debe devolver null si algún trustee falla en Round 1");
    }

}