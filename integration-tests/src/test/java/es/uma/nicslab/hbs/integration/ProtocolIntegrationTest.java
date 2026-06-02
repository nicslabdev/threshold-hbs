package es.uma.nicslab.hbs.integration;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.cas.CASServer;
import es.uma.nicslab.hbs.cas.BlobStore;
import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.cas.HttpCASReader;
import es.uma.nicslab.hbs.cas.HttpCASWriter;
import es.uma.nicslab.hbs.roles.*;
import es.uma.nicslab.hbs.trustee.SQLiteTrusteeState;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

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

    // -------------------------------------------------------------------------
    // Utilidad: crea trustees con SQLiteTrusteeState en memoria
    // -------------------------------------------------------------------------

    /**
     * Crea un Dealer que usa SQLiteTrusteeState para cada trustee.
     * Sobreescribe la creación de trustees del Dealer estándar usando
     * un factory que inyecta SQLiteTrusteeState en lugar de InMemory.
     */
    private SetupDealer setupWithSQLite(int k, int[][] coalitions) throws Exception {
        // Usamos el Dealer estándar con HttpCASWriter
        Dealer dealer = new Dealer(casWriter);
        SetupDealer result = dealer.setup(k, coalitions, LMS_PARAMS);

        // Reemplazamos los trustees del resultado con versiones SQLite
        // El Dealer ya configuró la keylist via setup(), así que
        // recreamos los trustees con SQLiteTrusteeState y reiniciamos
        // su keylist a partir de la CL ya publicada en el CAS.
        Trustee[] sqliteTrustees = new Trustee[k];
        for (int i = 0; i < k; i++) {
            SQLiteTrusteeState sqliteStore = new SQLiteTrusteeState(":memory:");

            // Reconstruimos la keylist para este trustee a partir de la CL
            int[] keyIDs = keyIDsForTrustee(i, result.getCl().length,
                    toIntArrayCoalitions(result.getCl()));
            sqliteStore.initKeyList(keyIDs);

            // Creamos el trustee con los mismos parámetros pero store SQLite
            Trustee original = result.getTrustees()[i];
            sqliteTrustees[i] = new Trustee(
                    original.getK(),
                    original.getLmotsParameters(),
                    original.getI(),
                    original.getLengthCHK(),
                    original.getLengthPath(),
                    sqliteStore
            );
        }

        return new SetupDealer(
                sqliteTrustees,
                result.getLmsPublicKey(),
                result.getCl(),
                result.getClCid()
        );
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

        byte[] message = "mensaje con CAS HTTP".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, result.getTrustees());

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

        byte[] message = "verificacion con CAS HTTP real".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, result.getTrustees());
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
        SetupDealer result = setupWithSQLite(3, coalitions);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        byte[] message = "mensaje con SQLite y CAS HTTP".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, result.getTrustees());

        assertNotNull(sig);
    }

    @Test
    void firma_verifica_lms_estandar_con_sqlite_y_cas_http() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        SetupDealer result = setupWithSQLite(3, coalitions);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        byte[] message = "verificacion con SQLite y CAS HTTP".getBytes();
        ThresholdSignature sig = agg.aggregatorSign(
                message, 0, result.getTrustees());
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
        SetupDealer result = setupWithSQLite(3, coalitions);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        byte[] message = "mensaje".getBytes();
        ThresholdSignature sig1 = agg.aggregatorSign(
                message, 0, result.getTrustees());
        assertNotNull(sig1);

        // Segunda firma con mismo keyID: SQLite garantiza que no está disponible
        ThresholdSignature sig2 = agg.aggregatorSign(
                message, 0, result.getTrustees());
        assertNull(sig2, "KeyID reutilizado debe devolver null con SQLite");
    }

    @Test
    void multiples_firmas_con_sqlite_y_cas_http() throws Exception {
        int[][] coalitions = buildCoalitions(3, 32);
        SetupDealer result = setupWithSQLite(3, coalitions);

        Aggregator agg = new Aggregator(
                result.getLmsPublicKey(), casReader, result.getClCid());

        for (int keyID = 0; keyID < 5; keyID++) {
            byte[] message = ("mensaje-" + keyID).getBytes();
            ThresholdSignature sig = agg.aggregatorSign(
                    message, keyID, result.getTrustees());
            assertNotNull(sig, "Firma nula para keyID=" + keyID);

            byte[] sigBytes = LMSSerializer.serialize(
                    sig, keyID, result.getLmsPublicKey());
            LMSSigner signer = new LMSSigner();
            signer.init(false, result.getLmsPublicKey());
            assertTrue(signer.verifySignature(message, sigBytes),
                    "Verificación fallida para keyID=" + keyID);
        }
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

    private static int[] keyIDsForTrustee(int trusteeIndex, int D,
                                          int[][] coalitions) {
        int count = 0;
        for (int keyID = 0; keyID < D; keyID++) {
            for (int m : coalitions[keyID]) {
                if (m == trusteeIndex) { count++; break; }
            }
        }
        int[] result = new int[count];
        int idx = 0;
        for (int keyID = 0; keyID < D; keyID++) {
            for (int m : coalitions[keyID]) {
                if (m == trusteeIndex) { result[idx++] = keyID; break; }
            }
        }
        return result;
    }

    private static int[][] toIntArrayCoalitions(
            es.uma.nicslab.hbs.protocol.CoalitionEntry[] cl) {
        int[][] result = new int[cl.length][];
        for (int i = 0; i < cl.length; i++) result[i] = cl[i].trustees();
        return result;
    }
}