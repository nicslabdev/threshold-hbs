package es.uma.nicslab.hbs.trustee;

import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Punto de entrada del contenedor Docker del Trustee.
 *
 * Arranca el servidor gRPC, registra TrusteeServiceImpl e intenta
 * recuperar el estado persistido si el contenedor se reinició.
 *
 * Configuración por variables de entorno:
 *   TRUSTEE_INDEX   Índice de este trustee en la coalición (obligatorio)
 *   TRUSTEE_PORT    Puerto gRPC de escucha (default: 9090)
 *   TRUSTEE_DB      Ruta al fichero SQLite (default: /db/trustee.db)
 *   TRUSTEE_CONFIG  Ruta al fichero de config (default: /db/trustee-config.bin)
 */
public class TrusteeGrpcServer {

    private static final Logger log = Logger.getLogger(TrusteeGrpcServer.class.getName());

    private static final int DEFAULT_PORT = 9090;
    private static final String DEFAULT_DB = "/db/trustee.db";
    private static final String DEFAULT_CONFIG = "/db/trustee-config.bin";
    private static final String DEFAULT_BULLETIN_BOARD = "/bulletin/board.json";
    private static final String DEFAULT_CAS_URL = "http://cas:8080";

    private final Server server;
    private final TrusteeServiceImpl service;

    public TrusteeGrpcServer(int trusteeIndex, int port, String dbPath, Path configPath, Path bulletingBoardPath, String casUrl) {
        this.service = new TrusteeServiceImpl(trusteeIndex, configPath, dbPath, bulletingBoardPath, casUrl);
        this.server = ServerBuilder.forPort(port)
                .addService(service)
                .build();
    }

    public void start() throws Exception {
        // Intentar recuperar estado si el contenedor se reinició
        service.tryRecover();

        server.start();
        log.info("Trustee " + service.getTrusteeIndex() + " escuchando en puerto " + server.getPort());

        // Hook de apagado limpio
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Apagando servidor gRPC del Trustee...");
            try {
                stop();
            } catch (Exception e) {
                log.warning("Error durante el apagado: " + e.getMessage());
            }
        }));
    }

    public void stop() throws Exception {
        if (server != null) {
            server.shutdown().awaitTermination(10, TimeUnit.SECONDS);
        }
    }

    public void blockUntilShutdown() throws InterruptedException {
        if (server != null) {
            server.awaitTermination();
        }
    }

    public static void main(String[] args) throws Exception {
        int trusteeIndex = intEnv("TRUSTEE_INDEX", -1);
        int port = intEnv("TRUSTEE_PORT", DEFAULT_PORT);
        String dbPath = strEnv("TRUSTEE_DB", DEFAULT_DB);
        Path configPath = Paths.get(strEnv("TRUSTEE_CONFIG", DEFAULT_CONFIG));
        Path bulletinBoardPath = Paths.get(strEnv("BULLETIN_BOARD_PATH", DEFAULT_BULLETIN_BOARD));
        String casUrl = strEnv("CAS_URL", DEFAULT_CAS_URL);

        if (trusteeIndex < 0) {
            System.err.println("ERROR: variable de entorno TRUSTEE_INDEX es obligatoria.");
            System.exit(1);
        }

        TrusteeGrpcServer server = new TrusteeGrpcServer(trusteeIndex, port, dbPath, configPath, bulletinBoardPath, casUrl);
        server.start();

        log.info(String.format("Trustee %d arrancado — puerto: %d, db: %s, config: %s", trusteeIndex, port, dbPath, configPath));

        server.blockUntilShutdown();
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
        return (val == null || val.isBlank()) ? defaultValue : val.trim();
    }

}