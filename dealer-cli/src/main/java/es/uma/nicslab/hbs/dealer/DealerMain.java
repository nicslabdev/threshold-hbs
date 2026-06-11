package es.uma.nicslab.hbs.dealer;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.cas.HttpCASWriter;
import es.uma.nicslab.hbs.grpc.SetupRequest;
import es.uma.nicslab.hbs.grpc.SetupResponse;
import es.uma.nicslab.hbs.grpc.TrusteeServiceGrpc;
import es.uma.nicslab.hbs.model.SetupDealer;
import es.uma.nicslab.hbs.protocol.BulletinBoard;
import es.uma.nicslab.hbs.roles.Dealer;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Punto de entrada del contenedor efímero del Dealer.
 *
 * Orquesta el setup distribuido completo:
 *   1. Lee setup-config.json
 *   2. Llama a Dealer.setup() → genera keypair, CRVs, publica en CAS
 *   3. Escribe BulletinBoard en el volumen compartido
 *   4. Para cada trustee: gRPC TrusteeService.Setup(K[t])
 *   5. Termina
 *
 * Variables de entorno:
 *   SETUP_CONFIG_PATH    Ruta al setup-config.json (obligatorio)
 *   BULLETIN_BOARD_PATH  Ruta donde escribir el board (default: /bulletin/board.json)
 *   TRUSTEE_URLS         Direcciones gRPC: "trustee-0:9090,trustee-1:9090,..."
 *   CAS_URL              URL del CAS (default: http://cas:8080)
 */
public class DealerMain {

    private static final Logger log = Logger.getLogger(DealerMain.class.getName());

    private static final String DEFAULT_BULLETIN_BOARD = "/bulletin/board.json";
    private static final String DEFAULT_CAS_URL = "http://cas:8080";
    private static final String DEFAULT_SETUP_CONFIG = "/config/setup-config.json";

    public static void main(String[] args) throws Exception {

        // ── Leer variables de entorno ─────────────────────────────────────────
        String setupConfigPath = strEnv("SETUP_CONFIG_PATH", DEFAULT_SETUP_CONFIG);
        String bulletinBoardStr = strEnv("BULLETIN_BOARD_PATH", DEFAULT_BULLETIN_BOARD);
        String trusteeUrlsStr = strEnv("TRUSTEE_URLS", null);
        String casUrl = strEnv("CAS_URL", DEFAULT_CAS_URL);

        if (trusteeUrlsStr == null || trusteeUrlsStr.isBlank()) {
            System.err.println("ERROR: TRUSTEE_URLS es obligatoria.");
            System.exit(1);
        }

        Path setupConfigFile = Paths.get(setupConfigPath);
        Path bulletinBoardPath = Paths.get(bulletinBoardStr);

        // ── 1. Leer configuración del setup ───────────────────────────────────
        log.info("Leyendo configuración desde: " + setupConfigFile);
        SetupConfig config = SetupConfig.loadFrom(setupConfigFile);
        log.info("k=" + config.getK() + ", lmsParams=" + config.getLmsParameters());

        // ── 2. Ejecutar setup criptográfico ───────────────────────────────────
        log.info("Ejecutando Dealer.setup()...");
        CASClient casClient = new CASClient(casUrl);
        HttpCASWriter casWriter = new HttpCASWriter(casClient);
        Dealer dealer = new Dealer(casWriter);

        int h = config.getLmsParameters().getLMSigParam().getH();
        int D = 1 << h; // 2^h
        int[][] coalitions = config.buildCoalitions(D);

        SetupDealer result = dealer.setup(config.getK(), coalitions, config.getLmsParameters());
        log.info("Setup completado. clCid=" + result.getClCid());

        // ── 3. Escribir BulletinBoard ─────────────────────────────────────────
        log.info("Escribiendo BulletinBoard en: " + bulletinBoardPath);
        BulletinBoard board = new BulletinBoard(
                result.getLmsPublicKey(),
                result.getClCid(),
                result.getLengthCHK(),
                result.getLengthPath()
        );
        board.saveTo(bulletinBoardPath);
        log.info("BulletinBoard escrito correctamente.");

        // ── 4. Enviar K[t] a cada trustee via gRPC ────────────────────────────
        String[] trusteeUrls = trusteeUrlsStr.split(",");
        int k = config.getK();

        if (trusteeUrls.length != k) {
            System.err.println("ERROR: TRUSTEE_URLS tiene " + trusteeUrls.length + " entradas pero k=" + k);
            System.exit(1);
        }

        byte[][] K = result.getK();

        for (int t = 0; t < k; t++) {
            String url = trusteeUrls[t].trim();
            log.info("Enviando Setup a trustee " + t + " en " + url);
            sendSetupToTrustee(url, K[t]);
            log.info("Trustee " + t + " configurado correctamente.");
        }

        // ── 5. Terminar ───────────────────────────────────────────────────────
        log.info("Setup distribuido completado. El Dealer termina.");
    }

    private static void sendSetupToTrustee(String hostPort, byte[] prfKey) throws Exception {
        String[] parts = hostPort.split(":");
        String host = parts[0];
        int port = Integer.parseInt(parts[1]);

        ManagedChannel channel = ManagedChannelBuilder
                .forAddress(host, port)
                .usePlaintext()
                .build();

        try {
            TrusteeServiceGrpc.TrusteeServiceBlockingStub stub = TrusteeServiceGrpc.newBlockingStub(channel);

            SetupRequest request = SetupRequest.newBuilder()
                    .setPrfKey(com.google.protobuf.ByteString.copyFrom(prfKey))
                    .build();

            SetupResponse response = stub.setup(request);

            if (!response.getOk()) {
                throw new RuntimeException("El trustee en " + hostPort + " rechazó el Setup.");
            }
        } finally {
            channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private static String strEnv(String name, String defaultValue) {
        String val = System.getenv(name);
        return (val == null || val.isBlank()) ? defaultValue : val.trim();
    }

}