package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.cas.HttpCASReader;
import es.uma.nicslab.hbs.grpc.*;
import es.uma.nicslab.hbs.protocol.BulletinBoard;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.roles.Trustee;
import es.uma.nicslab.hbs.model.Round1Msg;
import es.uma.nicslab.hbs.model.Round2Msg;
import es.uma.nicslab.hbs.util.ByteUtils;
import io.grpc.stub.StreamObserver;

import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Implementación del servicio gRPC TrusteeService.
 *
 * Traduce los mensajes Protobuf a llamadas a Trustee.java (lógica
 * criptográfica de core) y gestiona el ciclo de vida del estado
 * persistente (TrusteeConfig + SQLiteTrusteeState).
 *
 * Flujo de Setup:
 *   1. Dealer llama a Setup con la PRF_key.
 *   2. TrusteeServiceImpl persiste la config en TrusteeConfig.
 *   3. Descarga la CL del CAS y puebla la keylist en SQLite.
 *   4. Construye el objeto Trustee listo para firmar.
 *
 * Flujo de firma:
 *   1. Aggregator llama a ShardSign1 → trustee genera R_t y CHK_t.
 *   2. Aggregator llama a ShardSign2 → trustee genera Z_t y PATH_t.
 *   Si algún paso falla (keyID no disponible, estado inválido,
 *   verificación CHK fallida), el RPC devuelve abort=true.
 */
public class TrusteeServiceImpl extends TrusteeServiceGrpc.TrusteeServiceImplBase {

    private static final Logger log = Logger.getLogger(TrusteeServiceImpl.class.getName());

    private final int trusteeIndex;
    private final Path configPath; // ruta fichero config
    private final String dbPath; // ruta fichero SQLite
    private final Path bulletinBoardPath; // ruta fichero BulletinBoard
    private final String casUrl; // URL de red

    // Objetos que se construyen en Setup y se usan en las rondas de firma.
    // Son null hasta que Setup se completa correctamente.
    private volatile Trustee trustee;
    private volatile SQLiteTrusteeState stateStore;

    public TrusteeServiceImpl(int trusteeIndex, Path configPath, String dbPath, Path bulletinBoardPath, String casUrl) {
        this.trusteeIndex = trusteeIndex;
        this.configPath = configPath;
        this.dbPath = dbPath;
        this.bulletinBoardPath = bulletinBoardPath;
        this.casUrl = casUrl;
    }

    /**
     * Intenta recuperar el estado del trustee desde disco si ya fue
     * inicializado en una sesión anterior. Llamado por TrusteeGrpcServer
     * al arrancar.
     */
    public void tryRecover() {
        if (!TrusteeConfig.exists(configPath)) {
            log.info("Trustee " + trusteeIndex + ": no hay config persistida, esperando Setup del Dealer.");
            return;
        }
        try {
            TrusteeConfig config = TrusteeConfig.loadFrom(configPath);
            initFromConfig(config, false);
            log.info("Trustee " + trusteeIndex + ": estado recuperado desde disco correctamente.");
        } catch (Exception e) {
            log.warning("Trustee " + trusteeIndex + ": error recuperando estado: " + e.getMessage());
        }
    }

    @Override
    public void setup(SetupRequest request, StreamObserver<SetupResponse> responseObserver) {
        try {
            log.info("Trustee " + trusteeIndex + ": recibido Setup del Dealer.");

            // 1. Construir y persistir la configuración
            TrusteeConfig config = new TrusteeConfig(
                    request.getPrfKey().toByteArray()
            );
            config.saveTo(configPath);

            // 2. Inicializar trustee y state store desde la config
            initFromConfig(config, true);

            log.info("Trustee " + trusteeIndex + ": Setup completado.");
            responseObserver.onNext(SetupResponse.newBuilder().setOk(true).build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.severe("Trustee " + trusteeIndex + ": error en Setup: " + e.getMessage());
            responseObserver.onNext(SetupResponse.newBuilder().setOk(false).build());
            responseObserver.onCompleted();
        }
    }

    @Override
    public void shardSign1(Sign1Request request, StreamObserver<Sign1Response> responseObserver) {
        if (trustee == null) {
            log.warning("Trustee " + trusteeIndex + ": ShardSign1 rechazado — Setup no completado.");
            responseObserver.onNext(abort1());
            responseObserver.onCompleted();
            return;
        }

        int keyID = request.getKeyId();

        try {

            if (stateStore.hasAnySigningState()) {
                log.warning("Trustee " + trusteeIndex + ": firma rechazada — ya hay una firma en curso.");
                responseObserver.onNext(abort1());
                responseObserver.onCompleted();
                return;
            }

            // Ejecutamos lógica pura del core criptográfico
            byte[] keyIdBytes = ByteUtils.intToBytes(keyID);
            byte[] message = request.getMessage().toByteArray();

            Round1Msg round1 = trustee.shardSign1(keyIdBytes, message);

            if (round1 == null) {
                log.warning("Trustee " + trusteeIndex + ": ShardSign1 devolvió ⊥ para keyID=" + keyID);
                responseObserver.onNext(abort1());
            } else {
                // No llamar a stateStore.saveSigningState aquí — Trustee ya lo hace internamente
                responseObserver.onNext(Sign1Response.newBuilder()
                        .setRT(com.google.protobuf.ByteString.copyFrom(round1.getR_t()))
                        .setChkT(com.google.protobuf.ByteString.copyFrom(round1.getCHK_t()))
                        .setAbort(false)
                        .build());
            }
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.severe("Trustee " + trusteeIndex + ": error en ShardSign1 para keyID=" + keyID + ": " + e.getMessage());
            responseObserver.onNext(abort1());
            responseObserver.onCompleted();
        }
    }

    @Override
    public void shardSign2(Sign2Request request, StreamObserver<Sign2Response> responseObserver) {
        if (trustee == null) {
            log.warning("Trustee " + trusteeIndex + ": ShardSign2 rechazado — Setup no completado.");
            responseObserver.onNext(abort2());
            responseObserver.onCompleted();
            return;
        }

        int keyID = request.getKeyId();

        try {

            byte[] R = request.getR().toByteArray();
            byte[] chkI = request.getChkI().toByteArray();
            byte[] keyIdBytes = ByteUtils.intToBytes(keyID);

            // Pasamos los parámetros al core.
            Round2Msg round2 = trustee.shardSign2(keyIdBytes, R, chkI);

            if (round2 == null) {
                log.warning("Trustee " + trusteeIndex + ": ShardSign2 devolvió ⊥ para keyID=" + keyID);
                responseObserver.onNext(abort2());
            } else {
                responseObserver.onNext(Sign2Response.newBuilder()
                        .setPathT(com.google.protobuf.ByteString.copyFrom(round2.getPATH_t()))
                        .setZT(com.google.protobuf.ByteString.copyFrom(round2.getZ_t()))
                        .setAbort(false)
                        .build());
            }
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.severe("Trustee " + trusteeIndex + ": error en ShardSign2 para keyID=" + keyID + ": " + e.getMessage());
            responseObserver.onNext(abort2());
            responseObserver.onCompleted();
        }
    }

    public int getTrusteeIndex() { return trusteeIndex; }

    /**
     * Construye el Trustee y el SQLiteTrusteeState a partir de la config,
     * descarga la CL del CAS y puebla la keylist en SQLite.
     *
     * Llamado tanto desde Setup (primera vez) como desde tryRecover
     * (reinicios del contenedor).
     */
    private void initFromConfig(TrusteeConfig config, boolean isInitialSetup) throws Exception {

        BulletinBoard board = BulletinBoard.loadFrom(bulletinBoardPath);

        // Crear el state store SQLite
        SQLiteTrusteeState store = new SQLiteTrusteeState(dbPath);

        // Descargar la CL del CAS para obtener los keyIDs de este trustee
        CASClient casClient = new CASClient(casUrl);
        HttpCASReader casReader = new HttpCASReader(casClient);
        CoalitionEntry[] cl = casReader.getCL(board.getClCid());

        Trustee t = new Trustee(
                config.getK(),
                board.getLmsPublicKey().getOtsParameters(),
                board.getLmsPublicKey().getI(),
                board.getLengthCHK(),
                board.getLengthPATH(),
                store
        );

        // Inicializar la keylist solo si estamos en el setup, no en un intento de recuperar el estado
        if (isInitialSetup) {
            t.setup(trusteeIndex, cl);
        }

        // Asignación atómica: el trustee solo es visible cuando está listo
        this.stateStore = store;
        this.trustee = t;
    }

    private static Sign1Response abort1() {
        return Sign1Response.newBuilder().setAbort(true).build();
    }

    private static Sign2Response abort2() {
        return Sign2Response.newBuilder().setAbort(true).build();
    }

}