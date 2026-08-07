package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.util.ByteUtils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TrusteeTest {

    private static final LMSParameters LMS_PARAMS = new LMSParameters(
            LMSigParameters.lms_sha256_n32_h5,
            LMOtsParameters.sha256_n32_w4
    );
    private static final int INDEX_LIMIT = 32; // 2^h con h=5
    private static final int NUM_TRUSTEES = 3;

    private PublicBulletinBoard board;
    private Trustee[] trustees;
    private int[][] CL;
    private int n;

    /** Coaliciones de tamaño 2 rotando entre {0,1,2}: {0,1}, {1,2}, {0,2}, ... */
    @BeforeEach
    void setup() {
        CL = new int[INDEX_LIMIT][];
        for (int keyID = 0; keyID < INDEX_LIMIT; keyID++) {
            switch (keyID % 3) {
                case 0 -> CL[keyID] = new int[]{0, 1};
                case 1 -> CL[keyID] = new int[]{1, 2};
                case 2 -> CL[keyID] = new int[]{0, 2};
            }
        }

        Dealer dealer = new Dealer();
        SetupDealer setupDealer = dealer.ShardSetup(NUM_TRUSTEES, CL, LMS_PARAMS);
        board = setupDealer.getBoard();
        trustees = setupDealer.getTrustees();

        for (int t = 0; t < NUM_TRUSTEES; t++) {
            trustees[t].TrusteeSetup(t, CL);
        }

        n = board.getParameter().getN();
    }

    @Test
    void testShardSign1RejectsKeyIdNotInCoalition() {
        // keyID=0 pertenece a {0,1}; el trustee 2 no forma parte de esa coalición.
        byte[] keyIdBytes = ByteUtils.intToBytes(0);
        Round1Msg round1 = trustees[2].ShardSign1(keyIdBytes, "mensaje".getBytes());
        assertNull(round1, "un trustee fuera de la coalición debe devolver ⊥");
    }

    @Test
    void testShardSign1SucceedsForKeyIdInCoalition() {
        int keyID = 0; // coalición {0,1}
        byte[] keyIdBytes = ByteUtils.intToBytes(keyID);

        Round1Msg round1 = trustees[0].ShardSign1(keyIdBytes, "mensaje".getBytes());

        assertNotNull(round1, "un trustee de la coalición debe poder iniciar la Ronda 1");
        assertEquals(n, round1.getR_t().length, "R_t debe tener n bytes");

        assertEquals(board.getCRV(keyID).getCHK().length, round1.getCHK_t().length, "CHK_t debe tener el mismo tamaño que CRV.CHK (coalición*n)");
    }

    @Test
    void testShardSign1RejectsWhileSignatureInProgress() {
        // Trustee 0 pertenece tanto a keyID=0 como a keyID=3 (ambos {0,1})
        Round1Msg first = trustees[0].ShardSign1(ByteUtils.intToBytes(0), "primer mensaje".getBytes());
        assertNotNull(first);

        Round1Msg second = trustees[0].ShardSign1(ByteUtils.intToBytes(3), "otro mensaje".getBytes());
        assertNull(second, "no se puede iniciar una nueva firma mientras hay una en curso");
    }

    @Test
    void testShardSign2WithoutPriorShardSign1ReturnsNull() {
        byte[] fakeR = new byte[n];
        byte[] fakeCHK = new byte[n];
        Round2Msg round2 = trustees[0].ShardSign2(fakeR, fakeCHK);
        assertNull(round2, "ShardSign2 sin una Ronda 1 previa debe devolver ⊥");
    }

    @Test
    void testShardSign2RejectsInvalidCHKAndResetsState() {
        int keyID = 0; // coalición {0,1}
        byte[] keyIdBytes = ByteUtils.intToBytes(keyID);
        byte[] message = "mensaje".getBytes();

        Round1Msg r1_0 = trustees[0].ShardSign1(keyIdBytes, message);
        Round1Msg r1_1 = trustees[1].ShardSign1(keyIdBytes, message);
        assertNotNull(r1_0);
        assertNotNull(r1_1);

        CRV crv = board.getCRV(keyID);
        byte[] R = ByteUtils.xorAll(crv.getR(), new byte[][]{r1_0.getR_t(), r1_1.getR_t()});

        // CHK correcto para el trustee 0 sería CHK[0] tras deconcat (n bytes,
        // no el CHK_t completo de la Ronda 1, que mide coalición*n). Le pasamos
        // basura del tamaño esperado por KK_Auth para forzar el fallo.
        byte[] wrongCHK = new byte[n];
        java.util.Arrays.fill(wrongCHK, (byte) 0xFF);

        Round2Msg badRound2 = trustees[0].ShardSign2(R, wrongCHK);
        assertNull(badRound2, "KK_Auth debe rechazar un CHK que no coincide con el comprometido en la Ronda 1");

        // El estado (`current`) debe haberse limpiado incluso tras un fallo de autenticación,
        // permitiendo que el trustee inicie una firma nueva para otro keyID de su coalición.
        Round1Msg nextRound1 = trustees[0].ShardSign1(ByteUtils.intToBytes(3), "otro mensaje".getBytes());
        assertNotNull(nextRound1, "el estado debe resetearse tras un KK_Auth fallido, no debe quedar bloqueado");
    }

    @Test
    void testShardSign1RejectsReuseAfterCompletedRound() {
        int keyID = 0; // coalición {0,1}
        byte[] keyIdBytes = ByteUtils.intToBytes(keyID);
        byte[] message = "mensaje".getBytes();

        Round2Msg round2 = completeRound(trustees[0], trustees[1], keyID, message);
        assertNotNull(round2, "la primera firma sobre este keyID debe completarse con éxito");

        // El keyID ya fue consumido por el trustee 0 (removido de su keylist en ShardSign1).
        Round1Msg reuse = trustees[0].ShardSign1(keyIdBytes, "otro intento".getBytes());
        assertNull(reuse, "reutilizar un keyID ya firmado debe devolver ⊥ (protección one-time)");
    }

    @Test
    void testFullSoloCoalitionSignatureVerifies() throws Exception {
        // Coalición de tamaño 1: solo el trustee 0 firma para keyID=0.
        int[][] soloCL = new int[INDEX_LIMIT][];
        soloCL[0] = new int[]{0};
        for (int keyID = 1; keyID < INDEX_LIMIT; keyID++) {
            soloCL[keyID] = new int[]{0, 1}; // el resto no se usa en este test
        }

        Dealer dealer = new Dealer();
        SetupDealer setupDealer = dealer.ShardSetup(NUM_TRUSTEES, soloCL, LMS_PARAMS);
        PublicBulletinBoard soloBoard = setupDealer.getBoard();
        Trustee[] soloTrustees = setupDealer.getTrustees();
        soloTrustees[0].TrusteeSetup(0, soloCL);

        int keyID = 0;
        byte[] keyIdBytes = ByteUtils.intToBytes(keyID);
        byte[] message = "mensaje firmado en solitario".getBytes();
        CRV crv = soloBoard.getCRV(keyID);
        int localN = soloBoard.getParameter().getN();

        // Ronda 1
        Round1Msg round1 = soloTrustees[0].ShardSign1(keyIdBytes, message);
        assertNotNull(round1);

        byte[] R = ByteUtils.xorAll(crv.getR(), new byte[][]{round1.getR_t()});
        byte[] CHKConcat = ByteUtils.xorAll(crv.getCHK(), new byte[][]{round1.getCHK_t()});
        byte[][] CHK = ByteUtils.deconcat(CHKConcat, localN);
        assertEquals(1, CHK.length, "con coalición de tamaño 1 solo hay un bloque de CHK");

        // Ronda 2
        Round2Msg round2 = soloTrustees[0].ShardSign2(R, CHK[0]);
        assertNotNull(round2);

        byte[] PATHConcat = ByteUtils.xorAll(crv.getPATH(), new byte[][]{round2.getPATH_t()});
        byte[][] PATH = ByteUtils.deconcat(PATHConcat, localN);

        byte[] h = LMSHashUtils.computeH(soloBoard.getParameter(), soloBoard.getI(), keyID, R, message);
        byte[] Z_CRV = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(h, crv.getSK(), soloBoard.getParameter());
        byte[] Z = ByteUtils.xorAll(Z_CRV, new byte[][]{round2.getZ_t()});

        ThresholdSignature sig = new ThresholdSignature(R, PATH, Z);

        byte[] sigBytes = LMSSerializer.serialize(sig, soloBoard, keyID);
        LMSSigner signer = new LMSSigner();
        signer.init(false, soloBoard.getPublicKey());
        assertTrue(signer.verifySignature(message, sigBytes),
                "una firma reconstruida a partir de un único trustee (coalición k=1) debe verificar como LMS estándar");
    }

    /**
     * Ejecuta las dos rondas del protocolo entre dos trustees para un keyID dado,
     * reconstruyendo R y CHK exactamente como lo haría el Aggregator, y devuelve
     * el Round2Msg del primer trustee (o null si algo falló).
     */
    private Round2Msg completeRound(Trustee t0, Trustee t1, int keyID, byte[] message) {
        byte[] keyIdBytes = ByteUtils.intToBytes(keyID);

        Round1Msg r1_0 = t0.ShardSign1(keyIdBytes, message);
        Round1Msg r1_1 = t1.ShardSign1(keyIdBytes, message);
        if (r1_0 == null || r1_1 == null) return null;

        CRV crv = board.getCRV(keyID);
        byte[] R = ByteUtils.xorAll(crv.getR(), new byte[][]{r1_0.getR_t(), r1_1.getR_t()});
        byte[] CHKConcat = ByteUtils.xorAll(crv.getCHK(), new byte[][]{r1_0.getCHK_t(), r1_1.getCHK_t()});
        byte[][] CHK = ByteUtils.deconcat(CHKConcat, n);

        return t0.ShardSign2(R, CHK[0]);
    }

}