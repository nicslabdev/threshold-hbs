package es.uma.nicslab.hbs.integration;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.cas.CASServer;
import es.uma.nicslab.hbs.cas.BlobStore;
import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.cas.HttpCASReader;
import es.uma.nicslab.hbs.cas.HttpCASWriter;
import es.uma.nicslab.hbs.protocol.*;
import es.uma.nicslab.hbs.roles.*;
import es.uma.nicslab.hbs.trustee.SQLiteTrusteeState;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests de integración del protocolo threshold HBS completo.
 *
 * A diferencia de los tests unitarios de core (que usan InMemoryCASStore
 * e InMemoryTrusteeStateStore), estos tests usan las implementaciones reales:
 *
 *  - CasServer HTTP real levantado en localhost:19080
 *  - HttpCASWriter / HttpCASReader para comunicarse con el CAS
 *  - SQLiteTrusteeState con ":memory:" para persistencia real del trustee
 *
 * Esto verifica que la serialización, la red HTTP y la persistencia SQLite
 * funcionan correctamente de extremo a extremo antes de dockerizar.
 */
class ProtocolIntegrationTest {

    private static final int CAS_PORT = 19080;
    private static final String CAS_URL = "http://localhost:" + CAS_PORT;

    private static final LMSParameters LMS_PARAMS = new LMSParameters(
            LMSigParameters.lms_sha256_n32_h5,
            LMOtsParameters.sha256_n32_w4
    );

    @TempDir
    Path tempDir;

    CASServer casServer;
    CASClient casClient;
    HttpCASWriter casWriter;
    HttpCASReader casReader;

    @BeforeEach
    void setUp() throws Exception {
        // Levantar CAS HTTP real
        BlobStore store = new BlobStore(tempDir);
        casServer = new CASServer(store, CAS_PORT);
        casServer.start();

        casClient = new CASClient(CAS_URL);
        casWriter = new HttpCASWriter(casClient);
        casReader = new HttpCASReader(casClient);
    }

    @AfterEach
    void tearDown() {
        casServer.stop();
    }

    private Trustee[] createTrustees(SetupDealer result, boolean useSQLite)
            throws Exception {
        int k = result.getK().length;
        Trustee[] trustees = new Trustee[k];
        for (int i = 0; i < k; i++) {
            TrusteeState store = useSQLite
                    ? new SQLiteTrusteeState(":memory:")
                    : new InMemoryTrusteeState();
            trustees[i] = new Trustee(
                    result.getK()[i],
                    result.getLmsPublicKey().getOtsParameters(),
                    result.getLmsPublicKey().getI(),
                    result.getLengthCHK(),
                    result.getLengthPath(),
                    store
            );
            trustees[i].setup(i, result.getCl());
        }
        return trustees;
    }

    // -------------------------------------------------------------------------
    // Tests: Setup con CAS HTTP real
    // -------------------------------------------------------------------------

    @Test
    void setup_publica_crv_y_cl_en_cas_http() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        // Verificar que la CL se puede descargar del CAS
        assertNotNull(result.getClCid());
        var cl = casReader.getCL(result.getClCid());
        assertNotNull(cl);
        assertEquals(32, cl.length);

        // Verificar que cada CRV se puede descargar del CAS
        for (var entry : cl) {
            assertNotNull(entry.crvCid());
            var crv = casReader.getCRV(entry.crvCid());
            assertNotNull(crv);
            assertNotNull(crv.getR());
            assertNotNull(crv.getCHK());
            assertNotNull(crv.getPATH());
            assertNotNull(crv.getSK());
        }
    }

    // -------------------------------------------------------------------------
    // Tests: Firma con CAS HTTP real e InMemoryTrusteeState
    // -------------------------------------------------------------------------

    @Test
    void firma_shard_con_cas_http() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        TrusteeProxy[] proxies = Arrays.stream(createTrustees(result, false))
                .map(LocalTrusteeProxy::new)
                .toArray(TrusteeProxy[]::new);

        byte[] message = "mensaje con CAS HTTP".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, proxies);

        assertNotNull(sig);
        assertNotNull(sig.getR());
        assertNotNull(sig.getPATH());
        assertNotNull(sig.getZ());
    }

    @Test
    void firma_verifica_lms_estandar_con_cas_http() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        TrusteeProxy[] proxies = Arrays.stream(createTrustees(result, false))
                .map(LocalTrusteeProxy::new)
                .toArray(TrusteeProxy[]::new);

        byte[] message = "verificacion con CAS HTTP real".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, proxies);
        assertNotNull(sig);

        byte[] sigBytes = LMSSerializer.serialize(
                sig, 0, result.getLmsPublicKey());
        LMSSigner signer = new LMSSigner();
        signer.init(false, result.getLmsPublicKey());
        assertTrue(signer.verifySignature(message, sigBytes),
                "La firma threshold debe verificar como LMS estándar");
    }

    // -------------------------------------------------------------------------
    // Tests: Firma con CAS HTTP real y SQLiteTrusteeState
    // -------------------------------------------------------------------------

    @Test
    void firma_shard_con_cas_http_y_sqlite() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        TrusteeProxy[] proxies = Arrays.stream(createTrustees(result, true))
                .map(LocalTrusteeProxy::new)
                .toArray(TrusteeProxy[]::new);

        byte[] message = "mensaje con SQLite y CAS HTTP".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, proxies);

        assertNotNull(sig);
    }

    @Test
    void firma_verifica_lms_estandar_con_sqlite_y_cas_http() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        TrusteeProxy[] proxies = Arrays.stream(createTrustees(result, true))
                .map(LocalTrusteeProxy::new)
                .toArray(TrusteeProxy[]::new);

        byte[] message = "verificacion con SQLite y CAS HTTP".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, proxies);
        assertNotNull(sig);

        byte[] sigBytes = LMSSerializer.serialize(
                sig, 0, result.getLmsPublicKey());
        LMSSigner signer = new LMSSigner();
        signer.init(false, result.getLmsPublicKey());
        assertTrue(signer.verifySignature(message, sigBytes),
                "La firma con SQLite debe verificar como LMS estándar");
    }

    @Test
    void keyid_reutilizado_devuelve_null_con_sqlite() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        TrusteeProxy[] proxies = Arrays.stream(createTrustees(result, true))
                .map(LocalTrusteeProxy::new)
                .toArray(TrusteeProxy[]::new);

        byte[] message = "mensaje".getBytes();
        ThresholdSignature sig1 = agg.aggregatorSign(
                message, 0, proxies);
        assertNotNull(sig1);

        // Segunda firma con mismo keyID: SQLite garantiza que no está disponible
        ThresholdSignature sig2 = agg.aggregatorSign(
                message, 0, proxies);
        assertNull(sig2, "KeyID reutilizado debe devolver null con SQLite");
    }

    @Test
    void multiples_firmas_con_sqlite_y_cas_http() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        TrusteeProxy[] proxies = Arrays.stream(createTrustees(result, true))
                .map(LocalTrusteeProxy::new)
                .toArray(TrusteeProxy[]::new);

        for (int keyID = 0; keyID < 5; keyID++) {
            byte[] message = ("mensaje-" + keyID).getBytes();
            ThresholdSignature sig = agg.aggregatorSign(
                    message, keyID, proxies);
            assertNotNull(sig, "Firma nula para keyID=" + keyID);

            byte[] sigBytes = LMSSerializer.serialize(
                    sig, keyID, result.getLmsPublicKey());
            LMSSigner signer = new LMSSigner();
            signer.init(false, result.getLmsPublicKey());
            assertTrue(signer.verifySignature(message, sigBytes),
                    "Verificación fallida para keyID=" + keyID);
        }
    }

    @Test
    void dealer_escribe_bulletin_board_correcto() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(3, coalitions, LMS_PARAMS);

        Path boardPath = tempDir.resolve("board.json");
        BulletinBoard board = new BulletinBoard(
                result.getLmsPublicKey(),
                result.getClCid(),
                result.getLengthCHK(),
                result.getLengthPath()
        );
        board.saveTo(boardPath);

        BulletinBoard loaded = BulletinBoard.loadFrom(boardPath);
        assertArrayEquals(
                result.getLmsPublicKey().getEncoded(),
                loaded.getLmsPublicKey().getEncoded());
        assertEquals(result.getClCid(),      loaded.getClCid());
        assertEquals(result.getLengthCHK(),  loaded.getLengthCHK());
        assertEquals(result.getLengthPath(), loaded.getLengthPATH());
    }

    // -------------------------------------------------------------------------
    // Auxiliares
    // -------------------------------------------------------------------------

    private static int[][] buildCoalitions(int k, int D) {
        int[] all = new int[k];
        for (int i = 0; i < k; i++) all[i] = i;
        int[][] cl = new int[D][];
        for (int keyID = 0; keyID < D; keyID++) cl[keyID] = all.clone();
        return cl;
    }

}