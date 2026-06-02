package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.cas.HttpCASReader;
import es.uma.nicslab.hbs.grpc.*;
import es.uma.nicslab.hbs.lms.LMOtsParameters;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.protocol.SigningState;
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
 *   1. Dealer llama a Setup con los 7 parámetros del SetupRequest.
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

    // Índice de este trustee en la coalición (0-based).
    private final int trusteeIndex;

    // Ruta al fichero de configuración persistente.
    private final Path configPath;

    // Ruta al fichero SQLite de estado operacional.
    private final String dbPath;

    // Objetos que se construyen en Setup y se usan en las rondas de firma.
    // Son null hasta que Setup se completa correctamente.
    private volatile Trustee trustee;
    private volatile SQLiteTrusteeState stateStore;

    public TrusteeServiceImpl(int trusteeIndex, Path configPath, String dbPath) {
        this.trusteeIndex = trusteeIndex;
        this.configPath = configPath;
        this.dbPath = dbPath;
    }

    // -------------------------------------------------------------------------
    // Arranque: recuperar estado si el contenedor se reinició
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // RPC: Setup
    // -------------------------------------------------------------------------

    @Override
    public void setup(SetupRequest request, StreamObserver<SetupResponse> responseObserver) {
        try {
            log.info("Trustee " + trusteeIndex + ": recibido Setup del Dealer.");

            // 1. Construir y persistir la configuración
            TrusteeConfig config = new TrusteeConfig(
                    request.getPrfKey().toByteArray(),
                    request.getLmotsParamType(),
                    request.getI().toByteArray(),
                    request.getLengthChk(),
                    request.getLengthPath(),
                    request.getCasUrl(),
                    request.getClCid()
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

    // -------------------------------------------------------------------------
    // RPC: ShardSign1
    // -------------------------------------------------------------------------

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
            // Evaluamos la atómica reserva del KeyID en nuestro nuevo almacén SQLite
            if (!stateStore.claimKeyID(keyID)) {
                log.warning("Trustee " + trusteeIndex + ": Reutilización detectada o clave no asignada para keyID=" + keyID);
                responseObserver.onNext(abort1());
                responseObserver.onCompleted();
                return;
            }

            // Ejecutamos lógica pura de core criptográfico (ajusta conversión a bytes si tu core lo requiere)
            byte[] keyIdBytes = ByteUtils.intToBytes(keyID);
            byte[] message = request.getMessage().toByteArray();

            Round1Msg round1 = trustee.shardSign1(keyIdBytes, message);

            if (round1 == null) {
                log.warning("Trustee " + trusteeIndex + ": ShardSign1 devolvió ⊥ para keyID=" + keyID);
                responseObserver.onNext(abort1());
            } else {
                // Persistimos el estado en curso ("current") indexado por este KeyID atómicamente
                stateStore.saveSigningState(keyID, message);

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

    // -------------------------------------------------------------------------
    // RPC: ShardSign2
    // -------------------------------------------------------------------------

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
            // Intento atómico de Read-and-Delete para limpiar la sesión en SQLite
            SigningState session = stateStore.loadAndClearSigningState(keyID);
            if (session == null) {
                log.warning("Trustee " + trusteeIndex + ": No hay sesión de firma activa o re-entrada detectada para keyID=" + keyID);
                responseObserver.onNext(abort2());
                responseObserver.onCompleted();
                return;
            }

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

    // -------------------------------------------------------------------------
    // Inicialización interna
    // -------------------------------------------------------------------------

    /**
     * Construye el Trustee y el SQLiteTrusteeState a partir de la config,
     * descarga la CL del CAS y puebla la keylist en SQLite.
     *
     * Llamado tanto desde Setup (primera vez) como desde tryRecover
     * (reinicios del contenedor).
     */
    private void initFromConfig(TrusteeConfig config, boolean isInitialSetup) throws Exception {
        // Crear el state store SQLite
        SQLiteTrusteeState store = new SQLiteTrusteeState(dbPath);

        // Descargar la CL del CAS para obtener los keyIDs de este trustee
        CASClient casClient = new CASClient(config.getCasUrl());
        HttpCASReader casReader = new HttpCASReader(casClient);
        CoalitionEntry[] cl = casReader.getCL(config.getClCid());

        // Construir el Trustee con la config persistida
        LMOtsParameters params = config.getLmotsParameters();
        Trustee t = new Trustee(
                config.getK(),
                params,
                config.getI(),
                config.getLengthCHK(),
                config.getLengthPath(),
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

    // -------------------------------------------------------------------------
    // Respuestas de abort
    // -------------------------------------------------------------------------

    private static Sign1Response abort1() {
        return Sign1Response.newBuilder().setAbort(true).build();
    }

    private static Sign2Response abort2() {
        return Sign2Response.newBuilder().setAbort(true).build();
    }

    // -------------------------------------------------------------------------
    // Utilidades
    // -------------------------------------------------------------------------

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}