package es.uma.nicslab.hbs.cas;

import io.javalin.Javalin;
import io.javalin.http.Context;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Servidor HTTP del Content Addressable Storage.
 *
 * Expone dos endpoints sobre el BlobStore:
 *
 *   POST /blobs
 *     Body:    bytes crudos (application/octet-stream)
 *     Respuesta 201 Created
 *     Header:  Location: /blobs/{cid}
 *     Body:    {cid}  (texto plano, el SHA-256 hex del contenido)
 *
 *   GET /blobs/{cid}
 *     Respuesta 200 OK
 *     Body:    bytes crudos del blob
 *     — o —
 *     Respuesta 404 Not Found si el CID no existe
 *     Respuesta 400 Bad Request si el CID tiene formato inválido
 *
 * Configuración por variables de entorno:
 *   CAS_PORT      Puerto de escucha (default: 8080)
 *   CAS_DATA_DIR  Directorio de persistencia (default: /data)
 */
public class CASServer {

    private static final int DEFAULT_PORT = 8080;
    private static final String DEFAULT_DATA_DIR = "/data";

    private final Javalin app;
    private final BlobStore store;
    private final int port;

    public CASServer(BlobStore store, int port) {
        this.store = store;
        this.port = port;
        this.app = buildApp();
    }

    public void start() {
        app.start(port);
    }

    public void stop() {
        app.stop();
    }

    // -------------------------------------------------------------------------
    // Construcción de rutas
    // -------------------------------------------------------------------------

    private Javalin buildApp() {
        Javalin javalin = Javalin.create();
        javalin.post("/blobs", this::handlePut);
        javalin.get("/blobs/{cid}", this::handleGet);

        return javalin;
    }

    // -------------------------------------------------------------------------
    // Handlers
    // -------------------------------------------------------------------------

    /**
     * POST /blobs
     * Almacena el cuerpo de la petición como un blob y devuelve su CID.
     */
    private void handlePut(Context ctx) {
        byte[] blob = ctx.bodyAsBytes();

        if (blob.length == 0) {
            ctx.status(400).result("El cuerpo de la petición no puede estar vacío");
            return;
        }

        try {
            String cid = store.put(blob);
            ctx.status(201)
                    .header("Location", "/blobs/" + cid)
                    .contentType("text/plain")
                    .result(cid);
        } catch (IOException e) {
            ctx.status(500).result("Error al almacenar el blob: " + e.getMessage());
        }
    }

    /**
     * GET /blobs/{cid}
     * Recupera el blob identificado por el CID dado.
     */
    private void handleGet(Context ctx) {
        String cid = ctx.pathParam("cid");

        try {
            byte[] blob = store.get(cid);
            ctx.status(200)
                    .contentType("application/octet-stream")
                    .result(blob);
        } catch (IllegalArgumentException e) {
            ctx.status(400).result("CID inválido: " + e.getMessage());
        } catch (BlobStore.BlobNotFoundException e) {
            ctx.status(404).result("Blob no encontrado: " + cid);
        } catch (IOException e) {
            ctx.status(500).result("Error al leer el blob: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Punto de entrada
    // -------------------------------------------------------------------------

    public static void main(String[] args) throws IOException {
        int port = intEnv("CAS_PORT", DEFAULT_PORT);
        String dataDir = strEnv("CAS_DATA_DIR", DEFAULT_DATA_DIR);

        BlobStore store = new BlobStore(Paths.get(dataDir));
        new CASServer(store, port).start();

        System.out.printf("CAS arrancado en puerto %d, datos en %s%n", port, dataDir);
    }

    // -------------------------------------------------------------------------
    // Utilidades de configuración
    // -------------------------------------------------------------------------

    private static int intEnv(String name, int defaultValue) {
        String val = System.getenv(name);
        if (val == null || val.isBlank()) return defaultValue;
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            System.err.printf("Variable de entorno %s='%s' no es un entero válido, usando %d%n",
                    name, val, defaultValue);
            return defaultValue;
        }
    }

    private static String strEnv(String name, String defaultValue) {
        String val = System.getenv(name);
        return (val == null || val.isBlank()) ? defaultValue : val.trim();
    }
}