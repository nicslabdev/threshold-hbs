package es.uma.nicslab.hbs.cas;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class BlobStoreTest {

    @TempDir
    Path tempDir;
    BlobStore store;

    @BeforeEach
    void setUp() throws IOException {
        store = new BlobStore(tempDir);
    }

    // -------------------------------------------------------------------------
    // put()
    // -------------------------------------------------------------------------

    @Test
    void put_devuelve_sha256_del_contenido() throws IOException {
        byte[] blob = "hola mundo".getBytes();
        String cid = store.put(blob);

        String esperado = sha256hex(blob);
        assertEquals(esperado, cid);
    }

    @Test
    void put_cid_tiene_64_chars_hex_lowercase() throws IOException {
        String cid = store.put("test".getBytes());
        assertEquals(64, cid.length());
        assertTrue(cid.matches("[0-9a-f]+"));
    }

    @Test
    void put_mismo_blob_dos_veces_mismo_cid() throws IOException {
        byte[] blob = "contenido repetido".getBytes();
        String cid1 = store.put(blob);
        String cid2 = store.put(blob);
        assertEquals(cid1, cid2);
    }

    @Test
    void put_blobs_distintos_cids_distintos() throws IOException {
        String cid1 = store.put("blob A".getBytes());
        String cid2 = store.put("blob B".getBytes());
        assertNotEquals(cid1, cid2);
    }

    @Test
    void put_rechaza_blob_null() {
        assertThrows(IllegalArgumentException.class, () -> store.put(null));
    }

    @Test
    void put_rechaza_blob_vacio() {
        assertThrows(IllegalArgumentException.class, () -> store.put(new byte[0]));
    }

    // -------------------------------------------------------------------------
    // get()
    // -------------------------------------------------------------------------

    @Test
    void get_recupera_el_mismo_contenido() throws IOException {
        byte[] original = "contenido binario".getBytes();
        String cid = store.put(original);

        byte[] recuperado = store.get(cid);
        assertArrayEquals(original, recuperado);
    }

    @Test
    void get_blob_inexistente_lanza_BlobNotFoundException() {
        String cidFalso = "a".repeat(64);
        assertThrows(BlobStore.BlobNotFoundException.class, () -> store.get(cidFalso));
    }

    @Test
    void get_cid_invalido_lanza_IllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> store.get("corto"));
        assertThrows(IllegalArgumentException.class, () -> store.get(null));
        assertThrows(IllegalArgumentException.class, () -> store.get("Z".repeat(64))); // no hex
    }

    // -------------------------------------------------------------------------
    // verify()
    // -------------------------------------------------------------------------

    @Test
    void verify_blob_integro_devuelve_true() throws IOException {
        byte[] blob = "datos críticos".getBytes();
        String cid = store.put(blob);
        assertTrue(store.verify(cid));
    }

    // -------------------------------------------------------------------------
    // exists()
    // -------------------------------------------------------------------------

    @Test
    void exists_true_tras_put() throws IOException {
        String cid = store.put("existe".getBytes());
        assertTrue(store.exists(cid));
    }

    @Test
    void exists_false_si_no_se_ha_subido() {
        assertFalse(store.exists("b".repeat(64)));
    }

    // -------------------------------------------------------------------------
    // Datos binarios (relevante para CRV: arrays de bytes crudos)
    // -------------------------------------------------------------------------

    @Test
    void put_y_get_datos_binarios_arbitrarios() throws IOException {
        byte[] binario = new byte[9 * 1024]; // ~9 KiB, tamaño de un CRV típico
        for (int i = 0; i < binario.length; i++) {
            binario[i] = (byte) (i % 256);
        }

        String cid = store.put(binario);
        byte[] recuperado = store.get(cid);
        assertArrayEquals(binario, recuperado);
    }

    // -------------------------------------------------------------------------
    // Auxiliar
    // -------------------------------------------------------------------------

    private static String sha256hex(byte[] data) throws RuntimeException {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}