package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.protocol.SigningState;
import es.uma.nicslab.hbs.util.ByteUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitarios de SQLiteTrusteeState adaptados al diseño multi-KeyID concurrente.
 * Usan ":memory:" para no dejar ficheros en disco.
 */
class SQLiteTrusteeStateTest {

    SQLiteTrusteeState store;

    @BeforeEach
    void setUp() throws SQLException {
        store = new SQLiteTrusteeState(":memory:");
    }

    @AfterEach
    void tearDown() throws SQLException {
        store.close();
    }

    // -------------------------------------------------------------------------
    // initKeyList / claimKeyID
    // -------------------------------------------------------------------------

    @Test
    void initKeyList_y_claim_disponible() throws SQLException {
        store.initKeyList(new int[]{0, 1, 2});
        assertTrue(store.claimKeyID(0));
    }

    @Test
    void claim_keyid_no_disponible_devuelve_false() throws SQLException {
        store.initKeyList(new int[]{1, 2});
        assertFalse(store.claimKeyID(0));
    }

    @Test
    void claim_keyid_ya_reclamado_devuelve_false() throws SQLException {
        store.initKeyList(new int[]{0});
        assertTrue(store.claimKeyID(0));
        assertFalse(store.claimKeyID(0)); // segunda vez: ya no está (quemado atómico)
    }

    @Test
    void claim_elimina_el_keyid_del_store() throws SQLException {
        store.initKeyList(new int[]{0, 1, 2});
        store.claimKeyID(1);
        assertFalse(store.claimKeyID(1)); // ya no existe
        assertTrue(store.claimKeyID(0));  // los demás siguen disponibles
        assertTrue(store.claimKeyID(2));
    }

    @Test
    void initKeyList_reinicia_estado_previo() throws SQLException {
        store.initKeyList(new int[]{0, 1, 2});
        store.claimKeyID(0);
        // Re-inicializar con lista diferente
        store.initKeyList(new int[]{5, 6});
        assertFalse(store.claimKeyID(1)); // el anterior ya no existe
        assertTrue(store.claimKeyID(5));
        assertTrue(store.claimKeyID(6));
    }

    // -------------------------------------------------------------------------
    // saveSigningState / loadAndClearSigningState / hasSigningState
    // -------------------------------------------------------------------------

    @Test
    void hasSigningState_false_sin_estado() throws SQLException {
        assertFalse(store.hasSigningState(42)); // Ahora requiere especificar el KeyID
    }

    @Test
    void saveSigningState_y_hasSigningState_true() throws SQLException {
        int keyID = 42;

        store.saveSigningState(keyID, "msg".getBytes());
        assertTrue(store.hasSigningState(keyID));
    }

    @Test
    void loadAndClear_devuelve_estado_correcto() throws SQLException {
        int keyID = 5;
        byte[] message = "mensaje de prueba".getBytes();

        store.saveSigningState(keyID, message);
        SigningState state = store.loadAndClearSigningState(keyID); // Requiere parámetro entero

        assertNotNull(state);
        assertEquals(keyID, state.keyID()); // El Core sigue esperando bytes
        assertArrayEquals(message, state.message());
    }

    @Test
    void loadAndClear_borra_el_estado() throws SQLException {
        int keyID = 1;

        store.saveSigningState(keyID, "msg".getBytes());
        store.loadAndClearSigningState(keyID);

        assertFalse(store.hasSigningState(keyID));
        assertNull(store.loadAndClearSigningState(keyID));
    }

    @Test
    void loadAndClear_sin_estado_devuelve_null() throws SQLException {
        assertNull(store.loadAndClearSigningState(99));
    }

    @Test
    void soporta_multiples_estados_concurrentes_sin_sobreescribir() throws SQLException {
        // TEST CRÍTICO: Verifica que el nuevo diseño soporta múltiples firmas concurrentes
        int keyID1 = 10;
        int keyID2 = 20;

        store.saveSigningState(keyID1, "primero".getBytes());
        store.saveSigningState(keyID2, "segundo".getBytes()); // Ya no se sobreescriben

        SigningState state1 = store.loadAndClearSigningState(keyID1);
        SigningState state2 = store.loadAndClearSigningState(keyID2);

        assertNotNull(state1);
        assertNotNull(state2);
        assertArrayEquals("primero".getBytes(), state1.message());
        assertArrayEquals("segundo".getBytes(), state2.message());
    }

    // -------------------------------------------------------------------------
    // Ciclo completo Round1 → Round2
    // -------------------------------------------------------------------------

    @Test
    void ciclo_completo_round1_round2() throws SQLException {
        int keyID = 7;
        byte[] message = "mensaje threshold".getBytes();

        // Simula Round1: el trustee reclama el keyID y guarda el estado
        store.initKeyList(new int[]{7});
        assertTrue(store.claimKeyID(7));
        store.saveSigningState(keyID, message);
        assertTrue(store.hasSigningState(keyID));

        // Simula Round2: recupera y borra el estado de forma aislada
        SigningState state = store.loadAndClearSigningState(keyID);
        assertNotNull(state);
        assertEquals(keyID, state.keyID());
        assertArrayEquals(message, state.message());
        assertFalse(store.hasSigningState(keyID));

        // El keyID ya no se puede reutilizar jamás
        assertFalse(store.claimKeyID(7));
    }

    @Test
    void keyid_no_reutilizable_tras_firma() throws SQLException {
        store.initKeyList(new int[]{0, 1, 2});

        // Firma completa con keyID=0
        store.claimKeyID(0);
        store.saveSigningState(0, "msg".getBytes());
        store.loadAndClearSigningState(0);

        // Intento de reutilización maliciosa
        assertFalse(store.claimKeyID(0));

        // Los demás siguen estando listos para su uso
        assertTrue(store.claimKeyID(1));
        assertTrue(store.claimKeyID(2));
    }

    @Test
    void purgeExpiredSessions_limpia_solo_antiguas() throws SQLException, InterruptedException {
        int keyIDOld = 100;
        int keyIDNew = 200;

        store.saveSigningState(keyIDOld, "viejo".getBytes());
        Thread.sleep(50); // Forzamos paso del tiempo para expirar la primera sesión

        store.saveSigningState(keyIDNew, "nuevo".getBytes());

        // Purgamos las sesiones que tengan más de 30 milisegundos
        store.purgeExpiredSessions(30);

        assertFalse(store.hasSigningState(keyIDOld)); // Eliminada
        assertTrue(store.hasSigningState(keyIDNew));  // Preservada
    }
}