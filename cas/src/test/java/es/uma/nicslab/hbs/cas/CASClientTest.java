package es.uma.nicslab.hbs.cas;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests de integración del CasClient.
 * Levantan un CasServer real y verifican el cliente contra él.
 */
class CASClientTest {

    private static final int    TEST_PORT = 18081;
    private static final String BASE_URL  = "http://localhost:" + TEST_PORT;

    @TempDir
    Path tempDir;

    CASServer server;
    CASClient client;

    @BeforeEach
    void setUp() throws IOException {
        BlobStore store = new BlobStore(tempDir);
        server = new CASServer(store, TEST_PORT);
        server.start();
        client = new CASClient(BASE_URL);
    }

    @AfterEach
    void tearDown() {
        server.stop();
    }

    // -------------------------------------------------------------------------
    // put()
    // -------------------------------------------------------------------------

    @Test
    void put_devuelve_cid_valido() throws IOException {
        String cid = client.put("hola".getBytes());
        assertEquals(64, cid.length());
        assertTrue(cid.matches("[0-9a-f]+"));
    }

    @Test
    void put_mismo_contenido_mismo_cid() throws IOException {
        byte[] blob = "contenido repetido".getBytes();
        String cid1 = client.put(blob);
        String cid2 = client.put(blob);
        assertEquals(cid1, cid2);
    }

    @Test
    void put_rechaza_blob_null() {
        assertThrows(IllegalArgumentException.class, () -> client.put(null));
    }

    @Test
    void put_rechaza_blob_vacio() {
        assertThrows(IllegalArgumentException.class, () -> client.put(new byte[0]));
    }

    // -------------------------------------------------------------------------
    // get()
    // -------------------------------------------------------------------------

    @Test
    void get_recupera_contenido_correcto() throws IOException {
        byte[] original = "datos de prueba".getBytes();
        String cid = client.put(original);
        byte[] recuperado = client.get(cid);
        assertArrayEquals(original, recuperado);
    }

    @Test
    void get_verifica_integridad_automaticamente() throws IOException {
        // Si el servidor devuelve el blob correcto, no lanza excepción
        byte[] blob = "integridad ok".getBytes();
        String cid = client.put(blob);
        assertDoesNotThrow(() -> client.get(cid));
    }

    @Test
    void get_cid_inexistente_lanza_CasException() {
        assertThrows(CASClient.CasException.class,
                () -> client.get("a".repeat(64)));
    }

    @Test
    void get_cid_invalido_lanza_IllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> client.get("no-es-valido"));
    }

    // -------------------------------------------------------------------------
    // Ciclo completo con datos binarios (simula CRV real)
    // -------------------------------------------------------------------------

    @Test
    void ciclo_completo_datos_binarios() throws IOException {
        byte[] crv = new byte[9 * 1024];
        for (int i = 0; i < crv.length; i++) {
            crv[i] = (byte) (i % 256);
        }

        String cid       = client.put(crv);
        byte[] recuperado = client.get(cid);

        assertArrayEquals(crv, recuperado);
    }

    // -------------------------------------------------------------------------
    // URL con trailing slash (robustez)
    // -------------------------------------------------------------------------

    @Test
    void acepta_base_url_con_trailing_slash() throws IOException {
        CASClient clientConSlash = new CASClient(BASE_URL + "/");
        String cid = clientConSlash.put("test slash".getBytes());
        assertNotNull(cid);
        assertDoesNotThrow(() -> clientConSlash.get(cid));
    }
}