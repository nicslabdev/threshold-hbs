package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class DealerTest {

    private static final LMSParameters LMS_PARAMS = new LMSParameters(
            LMSigParameters.lms_sha256_n32_h5,
            LMOtsParameters.sha256_n32_w4
    );
    private static final int INDEX_LIMIT = 32; // 2^h con h=5
    private static final int NUM_TRUSTEES = 3;

    /** Coaliciones válidas de tamaño 2, rotando entre {0,1,2}. */
    private int[][] validCL() {
        int[][] CL = new int[INDEX_LIMIT][];
        for (int keyID = 0; keyID < INDEX_LIMIT; keyID++) {
            switch (keyID % 3) {
                case 0 -> CL[keyID] = new int[]{0, 1};
                case 1 -> CL[keyID] = new int[]{1, 2};
                case 2 -> CL[keyID] = new int[]{0, 2};
            }
        }
        return CL;
    }

    @Test
    void testShardSetupProducesBoardWithCorrectDimensions() {
        int[][] CL = validCL();
        Dealer dealer = new Dealer();
        SetupDealer setup = dealer.ShardSetup(NUM_TRUSTEES, CL, LMS_PARAMS);

        assertNotNull(setup);
        assertEquals(NUM_TRUSTEES, setup.getTrustees().length, "debe crear un Trustee por cada k");

        PublicBulletinBoard board = setup.getBoard();
        assertNotNull(board.getCRV(), "el CRV debe publicarse en el board");
        assertEquals(INDEX_LIMIT, board.getCRV().length, "debe haber un CRV por cada KeyID");
    }

    @Test
    void testCRVFieldSizesMatchLMSParameters() {
        int[][] CL = validCL();
        Dealer dealer = new Dealer();
        SetupDealer setup = dealer.ShardSetup(NUM_TRUSTEES, CL, LMS_PARAMS);
        PublicBulletinBoard board = setup.getBoard();

        int n = board.getParameter().getN();
        int p = board.getParameter().getP();
        int steps = 1 << board.getParameter().getW(); // 2^w
        int h = 5;

        int keyID = 0;
        CRV crv = board.getCRV(keyID);
        int coalitionSize = CL[keyID].length;

        assertEquals(n, crv.getR().length, "CRV.R debe tener n bytes");
        assertEquals(coalitionSize * n, crv.getCHK().length, "CRV.CHK debe tener |coalición|*n bytes (concat de un CHK[t] por trustee)");
        assertEquals(h * n, crv.getPATH().length, "CRV.PATH debe tener h*n bytes");

        byte[][][] SK = crv.getSK();
        assertEquals(p, SK.length, "CRV.SK debe tener p cadenas");
        assertEquals(steps, SK[0].length, "cada cadena debe tener 2^w pasos");
        assertEquals(n, SK[0][0].length, "cada paso de la cadena debe tener n bytes");
    }

    @Test
    void testDifferentKeyIDsProduceDifferentCRV() {
        int[][] CL = validCL();
        Dealer dealer = new Dealer();
        SetupDealer setup = dealer.ShardSetup(NUM_TRUSTEES, CL, LMS_PARAMS);
        PublicBulletinBoard board = setup.getBoard();

        // Sanity check: dos KeyIDs distintos no deben producir el mismo CRV.R
        byte[] r0 = board.getCRV(0).getR();
        byte[] r1 = board.getCRV(1).getR();
        assertFalse(java.util.Arrays.equals(r0, r1), "CRV.R no debería coincidir entre KeyIDs distintos");
    }

    @Test
    void testShardSetupThrowsWhenCLLengthMismatchesIndexLimit() {
        // indexLimit para h=5 es 32; aquí forzamos un CL más corto
        int[][] shortCL = new int[16][];
        for (int keyID = 0; keyID < shortCL.length; keyID++) {
            shortCL[keyID] = new int[]{0, 1};
        }

        Dealer dealer = new Dealer();
        assertThrows(IllegalArgumentException.class,
                () -> dealer.ShardSetup(NUM_TRUSTEES, shortCL, LMS_PARAMS),
                "CL.length distinto de indexLimit debe lanzar IllegalArgumentException");
    }

    @Test
    void testShardSetupThrowsWhenCoalitionIndexOutOfBounds() {
        int[][] CL = validCL();
        // Coalición con un índice de trustee inexistente (solo hay 0..NUM_TRUSTEES-1)
        CL[0] = new int[]{0, NUM_TRUSTEES + 2};

        Dealer dealer = new Dealer();
        assertThrows(IllegalArgumentException.class,
                () -> dealer.ShardSetup(NUM_TRUSTEES, CL, LMS_PARAMS),
                "un índice de coalición fuera de rango debe lanzar IllegalArgumentException");
    }

    @Test
    void testBoardExposesConsistentMetadata() {
        int[][] CL = validCL();
        Dealer dealer = new Dealer();
        SetupDealer setup = dealer.ShardSetup(NUM_TRUSTEES, CL, LMS_PARAMS);
        PublicBulletinBoard board = setup.getBoard();

        assertNotNull(board.getPublicKey(), "la clave pública LMS debe quedar publicada en el board");
        assertNotNull(board.getI(), "el identificador I del árbol debe quedar publicado");
        assertTrue(board.getI().length > 0);
        assertSame(CL, board.getCL(), "el board debe exponer la misma CL usada en el setup");
        assertEquals(LMS_PARAMS.getLMOTSParam(), board.getParameter(), "los parámetros OTS publicados deben coincidir con los usados en el setup");
    }

}