package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.LMOtsParameters;
import es.uma.nicslab.hbs.lms.LMSParameters;
import es.uma.nicslab.hbs.lms.LMSSerializer;
import es.uma.nicslab.hbs.lms.LMSigParameters;
import es.uma.nicslab.hbs.lms.LMSSigner;
import es.uma.nicslab.hbs.model.SetupDealer;
import es.uma.nicslab.hbs.model.ThresholdSignature;
import es.uma.nicslab.hbs.protocol.InMemoryCAS;
import es.uma.nicslab.hbs.protocol.InMemoryTrusteeState;
import es.uma.nicslab.hbs.protocol.LocalTrusteeProxy;
import es.uma.nicslab.hbs.protocol.TrusteeProxy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class AggregatorTest {

    private static final LMSParameters LMS_PARAMS = new LMSParameters(
            LMSigParameters.lms_sha256_n32_h5,
            LMOtsParameters.sha256_n32_w4
    );

    private static final int NUM_TRUSTEES = 3;
    private static final int INDEX_LIMIT = 32;

    private InMemoryCAS cas;
    private SetupDealer setup;
    private TrusteeProxy[] proxies;
    private Aggregator aggregator;

    @BeforeEach
    void setUp() throws Exception {
        int[][] coalitions = rotatingCoalitions();

        cas = new InMemoryCAS();

        Dealer dealer = new Dealer(cas);
        setup = dealer.setup(
                NUM_TRUSTEES,
                coalitions,
                LMS_PARAMS
        );

        proxies = createLocalProxies(setup);

        aggregator = new Aggregator(
                setup.getLmsPublicKey(),
                cas,
                setup.getClCid()
        );
    }

    @Test
    void aggregatorSignReturnsThresholdSignature() throws Exception {
        ThresholdSignature signature = aggregator.aggregatorSign(
                "test message".getBytes(StandardCharsets.UTF_8),
                0,
                proxies
        );

        assertNotNull(signature);
    }

    @Test
    void signatureFieldsHaveExpectedDimensions() throws Exception {
        int keyID = 0;
        byte[] message = "dimension test".getBytes(StandardCharsets.UTF_8);

        ThresholdSignature signature =
                aggregator.aggregatorSign(message, keyID, proxies);

        assertNotNull(signature);

        LMOtsParameters ots =
                setup.getLmsPublicKey().getOtsParameters();

        int n = ots.getN();
        int p = ots.getP();

        assertEquals(n, signature.getR().length);
        assertEquals(p * n, signature.getZ().length);

        assertEquals(5, signature.getPATH().length);

        for (byte[] node : signature.getPATH()) {
            assertEquals(n, node.length);
        }
    }

    @Test
    void generatedThresholdSignatureVerifiesAsStandardLms() throws Exception {
        int keyID = 0;
        byte[] message =
                "RFC 8554 verification test".getBytes(StandardCharsets.UTF_8);

        ThresholdSignature signature =
                aggregator.aggregatorSign(message, keyID, proxies);

        assertNotNull(signature);
        assertTrue(verify(signature, message, keyID));
    }

    @Test
    void differentCoalitionsProduceValidSignatures() throws Exception {
        /*
         * keyID 0 -> {0,1}
         * keyID 1 -> {1,2}
         * keyID 2 -> {0,2}
         */
        for (int keyID = 0; keyID < 3; keyID++) {
            byte[] message = (
                    "message for coalition " + keyID
            ).getBytes(StandardCharsets.UTF_8);

            ThresholdSignature signature =
                    aggregator.aggregatorSign(message, keyID, proxies);

            assertNotNull(
                    signature,
                    "Signing failed for keyID=" + keyID
            );

            assertTrue(
                    verify(signature, message, keyID),
                    "Signature failed verification for keyID=" + keyID
            );
        }
    }

    @Test
    void keyIdReuseIsRejected() throws Exception {
        int keyID = 0;

        ThresholdSignature first =
                aggregator.aggregatorSign(
                        "first use".getBytes(StandardCharsets.UTF_8),
                        keyID,
                        proxies
                );

        assertNotNull(first);

        ThresholdSignature reuse =
                aggregator.aggregatorSign(
                        "reuse attempt".getBytes(StandardCharsets.UTF_8),
                        keyID,
                        proxies
                );

        assertNull(
                reuse,
                "A consumed LMS KeyID must never be reused"
        );
    }

    @Test
    void signingOneKeyIdDoesNotConsumeAnotherKeyId() throws Exception {
        ThresholdSignature first =
                aggregator.aggregatorSign(
                        "keyID 0".getBytes(StandardCharsets.UTF_8),
                        0,
                        proxies
                );

        assertNotNull(first);

        /*
         * keyID=2 shares Trustee 0 with keyID=0, but it is an
         * independent one-time LMS leaf and must remain available.
         */
        byte[] secondMessage =
                "keyID 2".getBytes(StandardCharsets.UTF_8);

        ThresholdSignature second =
                aggregator.aggregatorSign(
                        secondMessage,
                        2,
                        proxies
                );

        assertNotNull(second);
        assertTrue(verify(second, secondMessage, 2));
    }

    @Test
    void tamperedMessageFailsVerification() throws Exception {
        int keyID = 5;

        byte[] original =
                "original message".getBytes(StandardCharsets.UTF_8);

        ThresholdSignature signature =
                aggregator.aggregatorSign(
                        original,
                        keyID,
                        proxies
                );

        assertNotNull(signature);

        assertTrue(verify(signature, original, keyID));

        byte[] tampered =
                "tampered message".getBytes(StandardCharsets.UTF_8);

        assertFalse(
                verify(signature, tampered, keyID),
                "An LMS signature must not verify for a different message"
        );
    }

    private boolean verify(
            ThresholdSignature signature,
            byte[] message,
            int keyID
    ) throws Exception {

        byte[] serialized = LMSSerializer.serialize(
                signature,
                keyID,
                setup.getLmsPublicKey()
        );

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, setup.getLmsPublicKey());

        return verifier.verifySignature(message, serialized);
    }

    private static TrusteeProxy[] createLocalProxies(
            SetupDealer setup
    ) throws Exception {

        TrusteeProxy[] proxies =
                new TrusteeProxy[NUM_TRUSTEES];

        for (int i = 0; i < NUM_TRUSTEES; i++) {
            Trustee trustee = new Trustee(
                    setup.getK()[i],
                    setup.getLmsPublicKey().getOtsParameters(),
                    setup.getLmsPublicKey().getI(),
                    setup.getLengthCHK(),
                    setup.getLengthPath(),
                    new InMemoryTrusteeState()
            );

            trustee.setup(i, setup.getCl());

            proxies[i] = new LocalTrusteeProxy(trustee);
        }

        return proxies;
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
}
