package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.util.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class AggregatorTest {

    /* private Aggregator aggregator;
    private Trustee[] trustees;
    private byte[] keyIdBytes;
    private byte[] message;
    private byte[] R;
    private LMOtsParameters parameter;
    private int n;
    private int k;
    PublicBulletinBoard board;

    @BeforeEach
    void setup() {

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
        LMSPublicKeyParameters lmsPublic = (LMSPublicKeyParameters) keyPair.getPublic();

        parameter = lmsPrivate.getOtsParameters();
        byte[] I = lmsPrivate.getI();
        n = parameter.getN();
        int keyId = lmsPrivate.getIndex();
        keyIdBytes = ByteUtils.intToBytes(keyId);
        message = "mensaje de prueba".getBytes();

        board = new PublicBulletinBoard(lmsPublic, parameter, I);

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
        Dealer dealer = new Dealer(board);
        dealer.KK_Setup(keys, keyIdBytes, SK, R, PATH);

        // Construir trustees y cargar shares
        trustees = new Trustee[k];
        for (int t = 0; t < k; t++) {
            trustees[t] = new Trustee(keys[t], board);
        }
        board.publishTrustees(trustees);

        // Aggregator
        aggregator = new Aggregator(board);
    }

    @Test
    void testFlujoCompletoDevuelveThresholdSignature() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes);
        assertNotNull(sig, "KK_Aggregator_Sign debe devolver ThresholdSignature");
    }

    @Test
    void testRTieneNBytes() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes);
        assertNotNull(sig);
        assertEquals(n, sig.getR().length, "R debe tener n bytes");
    }

    @Test
    void testZTienePNBytes() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes);
        assertNotNull(sig);
        assertEquals(parameter.getP() * n, sig.getZ().length, "Z debe tener p*n bytes");
    }

    @Test
    void testPATHTieneHNodos() {
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes);
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
        ThresholdSignature sig = aggregator.KK_Aggregator_Sign(message, keyIdBytes);
        assertNotNull(sig);
        assertArrayEquals(R, sig.getR(), "R reconstruido debe coincidir con R original del dealer");
    } */

}