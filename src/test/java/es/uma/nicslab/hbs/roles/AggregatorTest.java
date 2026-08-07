package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AggregatorTest {

    private Aggregator aggregator;
    private PublicBulletinBoard board;
    private Trustee[] trustees;
    private int[][] CL;
    private LMOtsParameters otsParameters;
    private int n;
    private int p;
    private int indexLimit;

    @BeforeEach
    void setup() {

        LMSParameters lmsParams = new LMSParameters(
                LMSigParameters.lms_sha256_n32_h5,
                LMOtsParameters.sha256_n32_w4
        );

        int numTrustees = 3;
        indexLimit = 32; // 2^h con h=5

        // Coaliciones de tamaño 2 rotando entre {0,1,2}: {0,1}, {1,2}, {0,2}, ...
        CL = new int[indexLimit][];
        for (int keyID = 0; keyID < indexLimit; keyID++) {
            switch (keyID % 3) {
                case 0 -> CL[keyID] = new int[]{0, 1};
                case 1 -> CL[keyID] = new int[]{1, 2};
                case 2 -> CL[keyID] = new int[]{0, 2};
            }
        }

        Dealer dealer = new Dealer();
        SetupDealer setup = dealer.ShardSetup(numTrustees, CL, lmsParams);

        board = setup.getBoard();
        trustees = setup.getTrustees();

        for (int t = 0; t < numTrustees; t++) {
            trustees[t].TrusteeSetup(t, CL);
        }

        otsParameters = board.getParameter();
        n = otsParameters.getN();
        p = otsParameters.getP();

        aggregator = new Aggregator(board);
    }

    @Test
    void testAggregatorSignReturnsSignature() {
        byte[] message = "mensaje de prueba".getBytes();
        ThresholdSignature sig = aggregator.AggregatorSign(message, 0);
        assertNotNull(sig, "AggregatorSign debe devolver una ThresholdSignature con una coalición válida");
    }

    @Test
    void testSignatureFieldSizes() {
        byte[] message = "mensaje de prueba".getBytes();
        ThresholdSignature sig = aggregator.AggregatorSign(message, 0);
        assertNotNull(sig);

        assertEquals(n, sig.getR().length, "R debe tener n bytes");
        assertEquals(p * n, sig.getZ().length, "Z debe tener p*n bytes");
        assertEquals(5, sig.getPATH().length, "PATH debe tener h=5 nodos");
        for (byte[] node : sig.getPATH()) {
            assertEquals(n, node.length, "cada nodo del PATH debe tener n bytes");
        }
    }

    @Test
    void testSignatureVerifiesWithLMS() throws Exception {
        byte[] message = "mensaje de prueba".getBytes();
        int keyID = 0;

        ThresholdSignature sig = aggregator.AggregatorSign(message, keyID);
        assertNotNull(sig);

        assertTrue(verify(sig, message, keyID), "la firma threshold debe verificar como una firma LMS estándar");
    }

    @Test
    void testDifferentCoalitionsProduceValidSignatures() throws Exception {
        // keyID=0 -> {0,1}, keyID=1 -> {1,2}, keyID=2 -> {0,2}
        for (int keyID = 0; keyID < 3; keyID++) {
            byte[] message = ("mensaje " + keyID).getBytes();
            ThresholdSignature sig = aggregator.AggregatorSign(message, keyID);
            assertNotNull(sig, "keyID=" + keyID + " no debería fallar");
            assertTrue(verify(sig, message, keyID), "keyID=" + keyID + " debe verificar correctamente");
        }
    }

    @Test
    void testKeyIDReuseIsRejected() {
        byte[] message = "primer uso".getBytes();
        ThresholdSignature first = aggregator.AggregatorSign(message, 0);
        assertNotNull(first, "el primer uso del keyID debe tener éxito");

        ThresholdSignature reuse = aggregator.AggregatorSign("segundo uso".getBytes(), 0);
        assertNull(reuse, "reutilizar un keyID ya firmado debe devolver ⊥ (null)");
    }

    @Test
    void testSigningOneKeyIDDoesNotConsumeItForOtherCoalitions() {
        // keyID=0 pertenece a {0,1}. Firmarlo no debe afectar a keyID=2, que
        // comparte al trustee 0 pero pertenece a la coalición {0,2}.
        aggregator.AggregatorSign("firma keyID 0".getBytes(), 0);

        ThresholdSignature sigOtherKeyId = aggregator.AggregatorSign("firma keyID 2".getBytes(), 2);
        assertNotNull(sigOtherKeyId, "firmar keyID=0 no debe impedir que el trustee 0 participe en otra coalición para keyID=2");
    }

    @Test
    void testTamperedMessageFailsVerification() throws Exception {
        byte[] message = "mensaje original".getBytes();
        int keyID = 5;

        ThresholdSignature sig = aggregator.AggregatorSign(message, keyID);
        assertNotNull(sig);

        // La firma es válida para el mensaje original...
        assertTrue(verify(sig, message, keyID));
        // ...pero no para uno distinto (h cambia, y por tanto Z ya no corresponde).
        assertFalse(verify(sig, "mensaje alterado".getBytes(), keyID), "la firma no debe verificar contra un mensaje distinto al firmado");
    }

    /** Serializa y verifica una ThresholdSignature con el verificador LMS de BouncyCastle. */
    private boolean verify(ThresholdSignature sig, byte[] message, int keyID) throws Exception {
        byte[] sigBytes = LMSSerializer.serialize(sig, board, keyID);
        LMSSigner signer = new LMSSigner();
        signer.init(false, board.getPublicKey());
        return signer.verifySignature(message, sigBytes);
    }

}