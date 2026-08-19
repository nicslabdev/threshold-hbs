package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.LMOtsParameters;
import es.uma.nicslab.hbs.lms.LMSParameters;
import es.uma.nicslab.hbs.lms.LMSSerializer;
import es.uma.nicslab.hbs.lms.LMSigParameters;
import es.uma.nicslab.hbs.lms.LMSSigner;
import es.uma.nicslab.hbs.model.CRV;
import es.uma.nicslab.hbs.model.Round1Msg;
import es.uma.nicslab.hbs.model.Round2Msg;
import es.uma.nicslab.hbs.model.SetupDealer;
import es.uma.nicslab.hbs.model.ThresholdSignature;
import es.uma.nicslab.hbs.protocol.InMemoryCAS;
import es.uma.nicslab.hbs.protocol.InMemoryTrusteeState;
import es.uma.nicslab.hbs.protocol.LocalTrusteeProxy;
import es.uma.nicslab.hbs.protocol.TrusteeProxy;
import es.uma.nicslab.hbs.util.ByteUtils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class TrusteeTest {

    private static final LMSParameters LMS_PARAMS = new LMSParameters(
            LMSigParameters.lms_sha256_n32_h5,
            LMOtsParameters.sha256_n32_w4
    );

    private static final int NUM_TRUSTEES = 3;
    private static final int INDEX_LIMIT = 32;

    private InMemoryCAS cas;
    private SetupDealer setup;
    private Trustee[] trustees;
    private int n;

    @BeforeEach
    void setUp() throws Exception {
        cas = new InMemoryCAS();

        Dealer dealer = new Dealer(cas);

        setup = dealer.setup(
                NUM_TRUSTEES,
                rotatingCoalitions(),
                LMS_PARAMS
        );

        trustees = new Trustee[NUM_TRUSTEES];

        for (int i = 0; i < NUM_TRUSTEES; i++) {
            trustees[i] = newTrustee(
                    setup,
                    i,
                    new InMemoryTrusteeState()
            );
        }

        n = setup.getLmsPublicKey()
                .getOtsParameters()
                .getN();
    }

    @Test
    void round1RejectsKeyIdOutsideTrusteeCoalition() throws Exception {
        /*
         * keyID=0 belongs to coalition {0,1}.
         * Trustee 2 must therefore reject it.
         */
        Round1Msg result = trustees[2].shardSign1(
                ByteUtils.intToBytes(0),
                "message".getBytes(StandardCharsets.UTF_8)
        );

        assertNull(result);
    }

    @Test
    void round1SucceedsForAssignedKeyId() throws Exception {
        int keyID = 0;

        Round1Msg result = trustees[0].shardSign1(
                ByteUtils.intToBytes(keyID),
                "message".getBytes(StandardCharsets.UTF_8)
        );

        assertNotNull(result);
        assertNotNull(result.getR_t());
        assertNotNull(result.getCHK_t());

        assertEquals(n, result.getR_t().length);
        assertEquals(
                setup.getLengthCHK(),
                result.getCHK_t().length
        );
    }

    @Test
    void round2WithoutPriorRound1ReturnsNull() throws Exception {
        Round2Msg result = trustees[0].shardSign2(
                ByteUtils.intToBytes(0),
                new byte[n],
                new byte[n]
        );

        assertNull(
                result,
                "Round 2 without a matching Round 1 must return null"
        );
    }

    @Test
    void invalidChkIsRejectedAndConsumesRoundState() throws Exception {
        int keyID = 0;
        byte[] message =
                "authenticated round".getBytes(StandardCharsets.UTF_8);

        RoundContext context =
                startTwoTrusteeRound(keyID, message);

        byte[] invalidCHK =
                context.chk()[0].clone();

        invalidCHK[0] ^= 0x01;

        Round2Msg rejected = trustees[0].shardSign2(
                ByteUtils.intToBytes(keyID),
                context.r(),
                invalidCHK
        );

        assertNull(rejected);

        /*
         * KK_Sign2 performs an atomic load-and-clear before authentication.
         * The same Round 1 state must therefore not be usable a second time,
         * even if the second CHK is correct.
         */
        Round2Msg secondAttempt = trustees[0].shardSign2(
                ByteUtils.intToBytes(keyID),
                context.r(),
                context.chk()[0]
        );

        assertNull(
                secondAttempt,
                "Round state must be consumed after the first Round 2 attempt"
        );
    }

    @Test
    void keyIdCannotBeReusedAfterCompletedSignature() throws Exception {
        int keyID = 0;

        RoundContext context = startTwoTrusteeRound(
                keyID,
                "first use".getBytes(StandardCharsets.UTF_8)
        );

        Round2Msg r2_0 = trustees[0].shardSign2(
                ByteUtils.intToBytes(keyID),
                context.r(),
                context.chk()[0]
        );

        Round2Msg r2_1 = trustees[1].shardSign2(
                ByteUtils.intToBytes(keyID),
                context.r(),
                context.chk()[1]
        );

        assertNotNull(r2_0);
        assertNotNull(r2_1);

        Round1Msg reuse = trustees[0].shardSign1(
                ByteUtils.intToBytes(keyID),
                "reuse".getBytes(StandardCharsets.UTF_8)
        );

        assertNull(
                reuse,
                "A consumed LMS KeyID must never become available again"
        );
    }

    @Test
    void differentKeyIdsCanBeInFlightConcurrently() throws Exception {
        /*
         * keyID=0 and keyID=3 both use coalition {0,1}.
         * The production SQLite state is keyed by KeyID, so both
         * signing operations may be between Round 1 and Round 2
         * simultaneously.
         */

        int keyID0 = 0;
        int keyID3 = 3;

        Round1Msg a0 = trustees[0].shardSign1(
                ByteUtils.intToBytes(keyID0),
                "message 0".getBytes(StandardCharsets.UTF_8)
        );

        Round1Msg b0 = trustees[1].shardSign1(
                ByteUtils.intToBytes(keyID0),
                "message 0".getBytes(StandardCharsets.UTF_8)
        );

        Round1Msg a3 = trustees[0].shardSign1(
                ByteUtils.intToBytes(keyID3),
                "message 3".getBytes(StandardCharsets.UTF_8)
        );

        Round1Msg b3 = trustees[1].shardSign1(
                ByteUtils.intToBytes(keyID3),
                "message 3".getBytes(StandardCharsets.UTF_8)
        );

        assertNotNull(a0);
        assertNotNull(b0);
        assertNotNull(a3);
        assertNotNull(b3);

        RoundContext context0 =
                reconstructRound1(keyID0, a0, b0);

        RoundContext context3 =
                reconstructRound1(keyID3, a3, b3);

        assertNotNull(
                trustees[0].shardSign2(
                        ByteUtils.intToBytes(keyID0),
                        context0.r(),
                        context0.chk()[0]
                )
        );

        assertNotNull(
                trustees[1].shardSign2(
                        ByteUtils.intToBytes(keyID0),
                        context0.r(),
                        context0.chk()[1]
                )
        );

        assertNotNull(
                trustees[0].shardSign2(
                        ByteUtils.intToBytes(keyID3),
                        context3.r(),
                        context3.chk()[0]
                )
        );

        assertNotNull(
                trustees[1].shardSign2(
                        ByteUtils.intToBytes(keyID3),
                        context3.r(),
                        context3.chk()[1]
                )
        );
    }

    @Test
    void round1SharesAreDeterministicForSameTrusteeAndKeyId()
            throws Exception {

        int keyID = 0;

        Trustee duplicate = newTrustee(
                setup,
                0,
                new InMemoryTrusteeState()
        );

        byte[] message =
                "determinism test".getBytes(StandardCharsets.UTF_8);

        Round1Msg first = trustees[0].shardSign1(
                ByteUtils.intToBytes(keyID),
                message
        );

        Round1Msg second = duplicate.shardSign1(
                ByteUtils.intToBytes(keyID),
                message
        );

        assertNotNull(first);
        assertNotNull(second);

        assertArrayEquals(
                first.getR_t(),
                second.getR_t()
        );

        assertArrayEquals(
                first.getCHK_t(),
                second.getCHK_t()
        );
    }

    @Test
    void singleTrusteeCoalitionProducesValidLmsSignature()
            throws Exception {

        int[][] soloCoalitions =
                new int[INDEX_LIMIT][];

        for (int keyID = 0; keyID < INDEX_LIMIT; keyID++) {
            soloCoalitions[keyID] = new int[]{0};
        }

        InMemoryCAS soloCas = new InMemoryCAS();

        Dealer soloDealer = new Dealer(soloCas);

        SetupDealer soloSetup = soloDealer.setup(
                1,
                soloCoalitions,
                LMS_PARAMS
        );

        Trustee soloTrustee = newTrustee(
                soloSetup,
                0,
                new InMemoryTrusteeState()
        );

        TrusteeProxy[] soloProxy = {
                new LocalTrusteeProxy(soloTrustee)
        };

        Aggregator aggregator = new Aggregator(
                soloSetup.getLmsPublicKey(),
                soloCas,
                soloSetup.getClCid()
        );

        int keyID = 0;

        byte[] message =
                "single trustee coalition"
                        .getBytes(StandardCharsets.UTF_8);

        ThresholdSignature signature =
                aggregator.aggregatorSign(
                        message,
                        keyID,
                        soloProxy
                );

        assertNotNull(signature);

        byte[] serialized = LMSSerializer.serialize(
                signature,
                keyID,
                soloSetup.getLmsPublicKey()
        );

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, soloSetup.getLmsPublicKey());

        assertTrue(
                verifier.verifySignature(
                        message,
                        serialized
                )
        );
    }

    private RoundContext startTwoTrusteeRound(
            int keyID,
            byte[] message
    ) throws Exception {

        Round1Msg first = trustees[0].shardSign1(
                ByteUtils.intToBytes(keyID),
                message
        );

        Round1Msg second = trustees[1].shardSign1(
                ByteUtils.intToBytes(keyID),
                message
        );

        assertNotNull(first);
        assertNotNull(second);

        return reconstructRound1(
                keyID,
                first,
                second
        );
    }

    private RoundContext reconstructRound1(
            int keyID,
            Round1Msg first,
            Round1Msg second
    ) {

        CRV crv = cas.getCRV(
                setup.getCl()[keyID].crvCid()
        );

        byte[] r = ByteUtils.xorAll(
                crv.getR(),
                new byte[][]{
                        first.getR_t(),
                        second.getR_t()
                }
        );

        byte[] chkConcat = ByteUtils.xorAll(
                crv.getCHK(),
                new byte[][]{
                        first.getCHK_t(),
                        second.getCHK_t()
                }
        );

        byte[][] chk =
                ByteUtils.deconcat(chkConcat, n);

        return new RoundContext(r, chk);
    }

    private static Trustee newTrustee(
            SetupDealer setup,
            int trusteeIndex,
            InMemoryTrusteeState state
    ) throws Exception {

        Trustee trustee = new Trustee(
                setup.getK()[trusteeIndex],
                setup.getLmsPublicKey().getOtsParameters(),
                setup.getLmsPublicKey().getI(),
                setup.getLengthCHK(),
                setup.getLengthPath(),
                state
        );

        trustee.setup(
                trusteeIndex,
                setup.getCl()
        );

        return trustee;
    }

    private static int[][] rotatingCoalitions() {
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

    private record RoundContext(
            byte[] r,
            byte[][] chk
    ) {}
}
