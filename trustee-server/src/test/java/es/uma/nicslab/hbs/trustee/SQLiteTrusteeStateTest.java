package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.protocol.SigningState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitarios de SQLiteTrusteeState.
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
        assertFalse(store.claimKeyID(0)); // segunda vez: ya no está
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
        assertFalse(store.hasSigningState());
    }

    @Test
    void saveSigningState_y_hasSigningState_true() throws SQLException {
        store.saveSigningState(new byte[]{1, 2}, "msg".getBytes());
        assertTrue(store.hasSigningState());
    }

    @Test
    void loadAndClear_devuelve_estado_correcto() throws SQLException {
        byte[] keyID   = new byte[]{0, 0, 0, 5};
        byte[] message = "mensaje de prueba".getBytes();

        store.saveSigningState(keyID, message);
        SigningState state = store.loadAndClearSigningState();

        assertNotNull(state);
        assertArrayEquals(keyID,   state.keyID());
        assertArrayEquals(message, state.message());
    }

    @Test
    void loadAndClear_borra_el_estado() throws SQLException {
        store.saveSigningState(new byte[]{1}, "msg".getBytes());
        store.loadAndClearSigningState();

        assertFalse(store.hasSigningState());
        assertNull(store.loadAndClearSigningState());
    }

    @Test
    void loadAndClear_sin_estado_devuelve_null() throws SQLException {
        assertNull(store.loadAndClearSigningState());
    }

    @Test
    void save_sobreescribe_estado_previo() throws SQLException {
        store.saveSigningState(new byte[]{1}, "primero".getBytes());
        store.saveSigningState(new byte[]{2}, "segundo".getBytes());

        SigningState state = store.loadAndClearSigningState();
        assertNotNull(state);
        assertArrayEquals("segundo".getBytes(), state.message());
    }

    // -------------------------------------------------------------------------
    // Ciclo completo Round1 → Round2
    // -------------------------------------------------------------------------

    @Test
    void ciclo_completo_round1_round2() throws SQLException {
        byte[] keyID   = new byte[]{0, 0, 0, 7};
        byte[] message = "mensaje threshold".getBytes();

        // Simula Round1: el trustee reclama el keyID y guarda el estado
        store.initKeyList(new int[]{7});
        assertTrue(store.claimKeyID(7));
        store.saveSigningState(keyID, message);
        assertTrue(store.hasSigningState());

        // Simula Round2: recupera y borra el estado
        SigningState state = store.loadAndClearSigningState();
        assertNotNull(state);
        assertArrayEquals(keyID,   state.keyID());
        assertArrayEquals(message, state.message());
        assertFalse(store.hasSigningState());

        // El keyID ya no se puede reutilizar
        assertFalse(store.claimKeyID(7));
    }

    @Test
    void keyid_no_reutilizable_tras_firma() throws SQLException {
        store.initKeyList(new int[]{0, 1, 2});

        // Firma completa con keyID=0
        store.claimKeyID(0);
        store.saveSigningState(new byte[]{0}, "msg".getBytes());
        store.loadAndClearSigningState();

        // Intento de reutilización
        assertFalse(store.claimKeyID(0));

        // Los demás siguen disponibles
        assertTrue(store.claimKeyID(1));
        assertTrue(store.claimKeyID(2));
    }
}