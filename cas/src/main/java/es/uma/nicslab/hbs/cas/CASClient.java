package es.uma.nicslab.hbs.cas;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Cliente HTTP para el Content Addressable Storage.
 *
 * Usado por dealer-cli para publicar el CRV y la CL en setup,
 * y por aggregator-server para descargarlos durante la firma.
 *
 * Configuración por variable de entorno:
 *   CAS_URL URL base del servidor CAS (default: http://localhost:8080)
 */
public class CASClient {

    private static final String DEFAULT_CAS_URL = "http://localhost:8080";

    private final String baseUrl;
    private final HttpClient http;

    public CASClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1)
                : baseUrl;
        this.http = HttpClient.newHttpClient();
    }

    /**
     * Lee la URL del CAS desde la variable de entorno CAS_URL.
     * Útil para instanciar el cliente en main() sin hardcodear la URL.
     */
    public static CASClient fromEnv() {
        String url = System.getenv("CAS_URL");
        return new CASClient(url != null && !url.isBlank() ? url : DEFAULT_CAS_URL);
    }

    // -------------------------------------------------------------------------
    // Operaciones públicas
    // -------------------------------------------------------------------------

    /**
     * Sube un blob al CAS y devuelve su CID.
     *
     * @param blob Contenido a almacenar.
     * @return CID (SHA-256 hex del contenido, 64 chars).
     * @throws CasException Si el servidor responde con error o hay problema de red.
     */
    public String put(byte[] blob) throws IOException {
        if (blob == null || blob.length == 0) {
            throw new IllegalArgumentException("El blob no puede ser null ni vacío");
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/blobs"))
                .header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(blob))
                .build();

        HttpResponse<String> response = send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 201) {
            throw new CasException("PUT /blobs falló con status "
                    + response.statusCode() + ": " + response.body());
        }

        return response.body().trim();
    }

    /**
     * Descarga un blob del CAS por su CID y verifica su integridad.
     *
     * La verificación es gratuita: recalcula el SHA-256 del contenido
     * descargado y lo compara con el CID solicitado. Si no coinciden,
     * el blob ha sido alterado en tránsito o en el servidor.
     *
     * @param cid SHA-256 hex del contenido (64 chars).
     * @return Contenido del blob.
     * @throws CasException      Si el servidor responde con error.
     * @throws IntegrityException Si el hash del blob descargado no coincide con el CID.
     */
    public byte[] get(String cid) throws IOException {
        validateCid(cid);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/blobs/" + cid))
                .GET()
                .build();

        HttpResponse<byte[]> response = send(request, HttpResponse.BodyHandlers.ofByteArray());

        if (response.statusCode() == 404) {
            throw new CasException("Blob no encontrado para CID: " + cid);
        }
        if (response.statusCode() != 200) {
            throw new CasException("GET /blobs/" + cid + " falló con status "
                    + response.statusCode());
        }

        byte[] blob = response.body();

        // Un CRV alterado en el CAS se detecta aquí antes de usarlo.
        String actualCid = sha256hex(blob);
        if (!actualCid.equals(cid)) {
            throw new IntegrityException(cid, actualCid);
        }

        return blob;
    }

    // -------------------------------------------------------------------------
    // Excepciones
    // -------------------------------------------------------------------------

    public static class CasException extends IOException {
        public CasException(String message) {
            super(message);
        }
    }

    /**
     * El hash del blob descargado no coincide con el CID solicitado.
     * Indica que el contenido ha sido alterado (en tránsito o en el servidor).
     */
    public static class IntegrityException extends CasException {
        private final String expectedCid;
        private final String actualCid;

        public IntegrityException(String expectedCid, String actualCid) {
            super("Fallo de integridad: CID esperado=" + expectedCid + ", CID real=" + actualCid);
            this.expectedCid = expectedCid;
            this.actualCid = actualCid;
        }

        public String getExpectedCid() { return expectedCid; }
        public String getActualCid() { return actualCid;   }
    }

    // -------------------------------------------------------------------------
    // Métodos privados
    // -------------------------------------------------------------------------

    private <T> HttpResponse<T> send(HttpRequest request,
                                     HttpResponse.BodyHandler<T> handler) throws IOException {
        try {
            return http.send(request, handler);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Petición HTTP interrumpida", e);
        }
    }

    private static void validateCid(String cid) {
        if (cid == null || cid.length() != 64 || !cid.matches("[0-9a-f]+")) {
            throw new IllegalArgumentException(
                    "CID inválido (debe ser SHA-256 hex lowercase de 64 chars): " + cid);
        }
    }

    private static String sha256hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }
}