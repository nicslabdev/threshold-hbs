package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.LMOtsParameters;
import es.uma.nicslab.hbs.lms.LMSParameters;
import es.uma.nicslab.hbs.lms.LMSigParameters;
import es.uma.nicslab.hbs.model.CRV;
import es.uma.nicslab.hbs.model.SetupDealer;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.protocol.InMemoryCAS;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DealerTest {

    private static final LMSParameters LMS_PARAMS = new LMSParameters(
            LMSigParameters.lms_sha256_n32_h5,
            LMOtsParameters.sha256_n32_w4
    );

    private static final int NUM_TRUSTEES = 3;
    private static final int INDEX_LIMIT = 32;

    private InMemoryCAS cas;
    private Dealer dealer;

    @BeforeEach
    void setUp() {
        cas = new InMemoryCAS();
        dealer = new Dealer(cas);
    }

    @Test
    void setupProducesExpectedPublicMaterial() throws Exception {
        int[][] coalitions = validCoalitions();

        SetupDealer setup = dealer.setup(
                NUM_TRUSTEES,
                coalitions,
                LMS_PARAMS
        );

        assertNotNull(setup);
        assertNotNull(setup.getLmsPublicKey());
        assertNotNull(setup.getClCid());

        assertEquals(NUM_TRUSTEES, setup.getK().length);
        assertEquals(INDEX_LIMIT, setup.getCl().length);

        CoalitionEntry[] storedCL =
                cas.getCL(setup.getClCid());

        assertEquals(INDEX_LIMIT, storedCL.length);
    }

    @Test
    void crvDimensionsMatchLmsParameters() throws Exception {
        SetupDealer setup = dealer.setup(
                NUM_TRUSTEES,
                validCoalitions(),
                LMS_PARAMS
        );

        LMOtsParameters ots =
                setup.getLmsPublicKey().getOtsParameters();

        int n = ots.getN();
        int p = ots.getP();
        int steps = 1 << ots.getW();

        CoalitionEntry entry = setup.getCl()[0];
        CRV crv = cas.getCRV(entry.crvCid());

        int coalitionSize = entry.trustees().length;

        assertEquals(n, crv.getR().length);
        assertEquals(coalitionSize * n, crv.getCHK().length);
        assertEquals(5 * n, crv.getPATH().length);

        assertEquals(
                crv.getCHK().length,
                setup.getLengthCHK()
        );

        assertEquals(
                crv.getPATH().length,
                setup.getLengthPath()
        );

        byte[][][] sk = crv.getSK();

        assertEquals(p, sk.length);
        assertEquals(steps, sk[0].length);
        assertEquals(n, sk[0][0].length);
    }

    @Test
    void coalitionListPreservesConfiguredCoalitions() throws Exception {
        int[][] coalitions = validCoalitions();

        SetupDealer setup = dealer.setup(
                NUM_TRUSTEES,
                coalitions,
                LMS_PARAMS
        );

        CoalitionEntry[] stored =
                cas.getCL(setup.getClCid());

        for (int keyID = 0; keyID < INDEX_LIMIT; keyID++) {
            assertArrayEquals(
                    coalitions[keyID],
                    stored[keyID].trustees(),
                    "Unexpected coalition for keyID=" + keyID
            );
        }
    }

    @Test
    void setupRejectsCoalitionListWithWrongLength() {
        int[][] invalid = new int[16][];

        assertThrows(
                IllegalArgumentException.class,
                () -> dealer.setup(
                        NUM_TRUSTEES,
                        invalid,
                        LMS_PARAMS
                )
        );
    }

    @Test
    void setupRejectsTrusteeIndexOutOfBounds() {
        int[][] coalitions = validCoalitions();

        coalitions[0] =
                new int[]{0, NUM_TRUSTEES + 1};

        assertThrows(
                IllegalArgumentException.class,
                () -> dealer.setup(
                        NUM_TRUSTEES,
                        coalitions,
                        LMS_PARAMS
                )
        );
    }

    @Test
    void allPublishedCrvsAreRetrievableFromCas() throws Exception {
        SetupDealer setup = dealer.setup(
                NUM_TRUSTEES,
                validCoalitions(),
                LMS_PARAMS
        );

        for (int keyID = 0; keyID < INDEX_LIMIT; keyID++) {
            CoalitionEntry entry = setup.getCl()[keyID];

            assertNotNull(entry.crvCid());

            CRV crv = cas.getCRV(entry.crvCid());

            assertNotNull(
                    crv,
                    "Missing CRV for keyID=" + keyID
            );
        }
    }

    private static int[][] validCoalitions() {
        int[][] coalitions = new int[INDEX_LIMIT][];

        for (int keyID = 0; keyID < INDEX_LIMIT; keyID++) {
            switch (keyID % 3) {
                case 0 -> coalitions[keyID] = new int[]{0, 1};
                case 1 -> coalitions[keyID] = new int[]{1, 2};
                case 2 -> coalitions[keyID] = new int[]{0, 2};
                default -> throw new IllegalStateException();
            }
        }

        return coalitions;
    }
}
