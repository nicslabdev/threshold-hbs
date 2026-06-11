package es.uma.nicslab.hbs.aggregator;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.cas.HttpCASReader;
import es.uma.nicslab.hbs.lms.LMSPublicKeyParameters;
import es.uma.nicslab.hbs.lms.LMSSerializer;
import es.uma.nicslab.hbs.model.ThresholdSignature;
import es.uma.nicslab.hbs.protocol.BulletinBoard;
import es.uma.nicslab.hbs.protocol.TrusteeProxy;
import es.uma.nicslab.hbs.roles.Aggregator;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.nio.file.Paths;
import java.util.logging.Logger;

/**
 * Servidor HTTP del Aggregator.
 *
 * Expone un único endpoint:
 *
 *   POST /sign/{keyID}
 *     Body: bytes crudos del mensaje a firmar
 *     Respuesta 200 OK
 *     Body: firma threshold serializada en formato RFC 8554 (bytes crudos)
 *     — o —
 *     Respuesta 503 Service Unavailable si algún trustee devuelve ⊥
 *     Respuesta 400 Bad Request si el keyID es inválido
 *     Respuesta 500 Internal Server Error si hay un error inesperado
 *
 * Configuración por variables de entorno:
 *   AGGREGATOR_PORT   Puerto de escucha (default: 8081)
 *   CAS_URL           URL del servidor CAS (default: http://cas:8080)
 *   CL_CID            CID de la Coalition List en el CAS (obligatorio)
 *   TRUSTEE_URLS      Lista de host:port de trustees separada por comas
 *                     (p.ej. "trustee-0:9090,trustee-1:9090,trustee-2:9090")
 *   LMS_PUBLIC_KEY    Clave pública LMS en hexadecimal (obligatorio)
 */
public class AggregatorServer {

    private static final Logger log = Logger.getLogger(AggregatorServer.class.getName());

    private static final int DEFAULT_PORT = 8081;
    private static final String DEFAULT_CAS_URL = "http://cas:8080";

    private final Javalin app;
    private final Aggregator aggregator;
    private final TrusteeProxy[] trustees;
    private final LMSPublicKeyParameters lmsPublicKey;
    private final int port;

    public AggregatorServer(Aggregator aggregator, TrusteeProxy[] trustees, LMSPublicKeyParameters lmsPublicKey, int port) {
        this.aggregator = aggregator;
        this.trustees = trustees;
        this.lmsPublicKey = lmsPublicKey;
        this.port = port;
        this.app = buildApp();
    }

    public void start() {
        app.start(port);
        log.info("AggregatorServer arrancado en puerto " + port);
    }

    public void stop() {
        app.stop();
    }

    private Javalin buildApp() {
        Javalin javalin = Javalin.create();
        javalin.post("/sign/{keyID}", this::handleSign);
        return javalin;
    }

    /**
     * POST /sign/{keyID}
     * Firma el body de la petición con el KeyID indicado en la URL.
     */
    private void handleSign(Context ctx) {
        String keyIDStr = ctx.pathParam("keyID");
        int keyID;

        try {
            keyID = Integer.parseInt(keyIDStr);
        } catch (NumberFormatException e) {
            ctx.status(400).result("KeyID inválido: " + keyIDStr);
            return;
        }

        byte[] message = ctx.bodyAsBytes();
        if (message == null || message.length == 0) {
            ctx.status(400).result("El cuerpo de la petición no puede estar vacío");
            return;
        }

        try {
            ThresholdSignature sig = aggregator.aggregatorSign(message, keyID, trustees);

            if (sig == null) {
                log.warning("aggregatorSign devolvió ⊥ para keyID=" + keyID);
                ctx.status(503).result("Firma rechazada: algún trustee devolvió ⊥ para keyID=" + keyID);
                return;
            }

            // Serializar la firma al formato RFC 8554
            byte[] sigBytes = LMSSerializer.serialize(sig, keyID, lmsPublicKey);

            ctx.status(200).contentType("application/octet-stream").result(sigBytes);

        } catch (Exception e) {
            log.severe("Error firmando keyID=" + keyID + ": " + e.getMessage());
            ctx.status(500).result("Error interno: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        int port = intEnv("AGGREGATOR_PORT", DEFAULT_PORT);
        String casUrl = strEnv("CAS_URL", DEFAULT_CAS_URL);
        String trusteeUrlsStr = strEnv("TRUSTEE_URLS", null);
        String boardPath = strEnv("BULLETIN_BOARD_PATH", "/bulletin/board.json");

        if (trusteeUrlsStr == null || trusteeUrlsStr.isBlank()) {
            System.err.println("ERROR: variable de entorno TRUSTEE_URLS es obligatoria.");
            System.exit(1);
        }

        // Leer clave pública y clCid del bulletin board
        BulletinBoard board = BulletinBoard.loadFrom(Paths.get(boardPath));
        LMSPublicKeyParameters lmsPublicKey = board.getLmsPublicKey();
        String clCid = board.getClCid();

        // Construir proxies gRPC para cada trustee
        String[] trusteeUrls = trusteeUrlsStr.split(",");
        TrusteeProxy[] trustees = new TrusteeProxy[trusteeUrls.length];
        for (int i = 0; i < trusteeUrls.length; i++) {
            String[] parts = trusteeUrls[i].trim().split(":");
            String host = parts[0];
            int tPort = Integer.parseInt(parts[1]);
            trustees[i] = new GrpcTrusteeProxy(host, tPort);
            log.info("Trustee proxy " + i + " → " + trusteeUrls[i].trim());
        }

        // Construir CASReader y Aggregator
        CASClient casClient = new CASClient(casUrl);
        HttpCASReader casReader = new HttpCASReader(casClient);
        Aggregator aggregator = new Aggregator(lmsPublicKey, casReader, clCid);

        // Arrancar servidor
        new AggregatorServer(aggregator, trustees, lmsPublicKey, port).start();
    }

    private static int intEnv(String name, int defaultValue) {
        String val = System.getenv(name);
        if (val == null || val.isBlank()) return defaultValue;
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            log.warning("Variable de entorno " + name + "='" + val + "' no es un entero válido, usando " + defaultValue);
            return defaultValue;
        }
    }

    private static String strEnv(String name, String defaultValue) {
        String val = System.getenv(name);
        return (val == null || val.isBlank()) ? defaultValue : val;
    }

}