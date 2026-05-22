package es.uma.nicslab.hbs.cas;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests de integración del CasServer.
 * Levantan un servidor real en un puerto aleatorio y hacen peticiones HTTP.
 */
class CASServerTest {

    // Puerto fijo para tests; en CI podría cambiarse a 0 + detección dinámica
    private static final int TEST_PORT = 18080;

    @TempDir
    Path tempDir;

    CASServer server;
    HttpClient http;

    @BeforeEach
    void setUp() throws IOException {
        BlobStore store = new BlobStore(tempDir);
        server = new CASServer(store, TEST_PORT);
        server.start();
        http = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        server.stop();
    }

    // -------------------------------------------------------------------------
    // POST /blobs
    // -------------------------------------------------------------------------

    @Test
    void post_devuelve_201_y_cid_en_body() throws Exception {
        byte[] blob = "contenido de prueba".getBytes();

        HttpResponse<String> response = post(blob);

        assertEquals(201, response.statusCode());
        String cid = response.body();
        assertEquals(64, cid.length());
        assertTrue(cid.matches("[0-9a-f]+"));
    }

    @Test
    void post_location_header_contiene_el_cid() throws Exception {
        byte[] blob = "blob con location".getBytes();

        HttpResponse<String> response = post(blob);

        String cid = response.body();
        String location = response.headers().firstValue("Location").orElse("");
        assertEquals("/blobs/" + cid, location);
    }

    @Test
    void post_cid_coincide_con_sha256_del_contenido() throws Exception {
        byte[] blob = "verificar hash".getBytes();

        HttpResponse<String> response = post(blob);

        String cidRecibido = response.body();
        String cidEsperado = sha256hex(blob);
        assertEquals(cidEsperado, cidRecibido);
    }

    @Test
    void post_mismo_blob_dos_veces_mismo_cid() throws Exception {
        byte[] blob = "blob repetido".getBytes();

        String cid1 = post(blob).body();
        String cid2 = post(blob).body();

        assertEquals(cid1, cid2);
    }

    @Test
    void post_body_vacio_devuelve_400() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + TEST_PORT + "/blobs"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> response = http.send(request,
                HttpResponse.BodyHandlers.ofString());

        assertEquals(400, response.statusCode());
    }

    // -------------------------------------------------------------------------
    // GET /blobs/{cid}
    // -------------------------------------------------------------------------

    @Test
    void get_recupera_el_blob_subido() throws Exception {
        byte[] original = "datos a recuperar".getBytes();
        String cid = post(original).body();

        HttpResponse<byte[]> response = get(cid);

        assertEquals(200, response.statusCode());
        assertArrayEquals(original, response.body());
    }

    @Test
    void get_content_type_es_octet_stream() throws Exception {
        String cid = post("binario".getBytes()).body();

        HttpResponse<byte[]> response = get(cid);

        String contentType = response.headers()
                .firstValue("Content-Type").orElse("");
        assertTrue(contentType.contains("application/octet-stream"));
    }

    @Test
    void get_cid_inexistente_devuelve_404() throws Exception {
        HttpResponse<byte[]> response = get("a".repeat(64));
        assertEquals(404, response.statusCode());
    }

    @Test
    void get_cid_invalido_devuelve_400() throws Exception {
        HttpResponse<byte[]> response = get("no-es-un-cid-valido");
        assertEquals(400, response.statusCode());
    }

    // -------------------------------------------------------------------------
    // Ciclo completo: POST → GET, datos binarios (simula un CRV)
    // -------------------------------------------------------------------------

    @Test
    void ciclo_completo_con_datos_binarios() throws Exception {
        // Simula el tamaño de un CRV real (~9 KiB)
        byte[] crv = new byte[9 * 1024];
        for (int i = 0; i < crv.length; i++) {
            crv[i] = (byte) (i % 256);
        }

        String cid = post(crv).body();
        byte[] recuperado = get(cid).body();

        assertArrayEquals(crv, recuperado);
        // Verificación de integridad: el CID debe coincidir con el SHA-256
        assertEquals(sha256hex(crv), cid);
    }

    // -------------------------------------------------------------------------
    // Utilidades
    // -------------------------------------------------------------------------

    private HttpResponse<String> post(byte[] blob) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + TEST_PORT + "/blobs"))
                .header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(blob))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<byte[]> get(String cid) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + TEST_PORT + "/blobs/" + cid))
                .GET()
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    private static String sha256hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}