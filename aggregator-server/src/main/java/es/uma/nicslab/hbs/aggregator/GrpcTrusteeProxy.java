package es.uma.nicslab.hbs.aggregator;

import es.uma.nicslab.hbs.grpc.*;
import es.uma.nicslab.hbs.model.Round1Msg;
import es.uma.nicslab.hbs.model.Round2Msg;
import es.uma.nicslab.hbs.protocol.TrusteeProxy;
import es.uma.nicslab.hbs.util.ByteUtils;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.util.concurrent.TimeUnit;

/**
 * Implementación gRPC de TrusteeProxy.
 *
 * Encapsula la comunicación con un Trustee remoto via gRPC.
 * Cada instancia representa un único trustee identificado por su
 * dirección (host:port).
 *
 * Además registra, cuando KLL_METRICS_FILE está configurado, el tamaño
 * serializado Protobuf de request y response para cada RPC de firma.
 *
 * Los byte counts representan payload Protobuf de aplicación. No incluyen
 * framing gRPC/HTTP2, TCP/IP ni otros headers de transporte.
 *
 * Uso típico:
 *   GrpcTrusteeProxy proxy = new GrpcTrusteeProxy("trustee-1", 9090);
 *   Round1Msg r1 = proxy.shardSign1(keyID, message);
 *   Round2Msg r2 = proxy.shardSign2(keyID, R, chkI);
 *   proxy.shutdown();
 */
public class GrpcTrusteeProxy implements TrusteeProxy {

    private final ManagedChannel channel;
    private final TrusteeServiceGrpc.TrusteeServiceBlockingStub stub;
    private final String address;

    /**
     * @param host Host del trustee (nombre del contenedor Docker o IP).
     * @param port Puerto gRPC del trustee (default 9090).
     */
    public GrpcTrusteeProxy(String host, int port) {
        this.address = host + ":" + port;
        this.channel = ManagedChannelBuilder
                .forAddress(host, port)
                .usePlaintext()  // sin TLS en el prototipo. Es suficiente porque los contenedores se comunican dentro de la red privada de Docker. En producción se sustituiría por .useTransportSecurity() con certificados
                .defaultLoadBalancingPolicy("pick_first")
                .build();
        this.stub = TrusteeServiceGrpc.newBlockingStub(channel); // el stub bloqueante es el más simple, la llamada espera hasta recibir la respuesta
    }

    @Override
    public Round1Msg shardSign1(byte[] keyID, byte[] message) throws Exception {
        int keyIDInt = ByteUtils.bytesToInt(keyID);

        Sign1Request request = Sign1Request.newBuilder()
                .setKeyId(keyIDInt)
                .setMessage(com.google.protobuf.ByteString.copyFrom(message))
                .build();

        int requestProtoBytes = request.getSerializedSize();
        int responseProtoBytes = -1;
        String status = "exception";

        try {
            Sign1Response response = stub.shardSign1(request);

            if (response.getAbort()) {
                status = "abort";
                return null; // ⊥ — el trustee rechazó la firma
            }

            Round1Msg result =
                new Round1Msg(
                    response.getRT().toByteArray(),
                    response.getChkT().toByteArray()
                );

            status = "success";

            return result;
        } finally {
            emitByteMetrics(
                    "grpc_client_round1",
                    keyIDInt,
                    status,
                    requestProtoBytes,
                    responseProtoBytes
            );
        }
    }

    @Override
    public Round2Msg shardSign2(byte[] keyID, byte[] R, byte[] chkI) throws Exception {
        int keyIDInt = ByteUtils.bytesToInt(keyID);

        Sign2Request request = Sign2Request.newBuilder()
                .setKeyId(keyIDInt)
                .setR(com.google.protobuf.ByteString.copyFrom(R))
                .setChkI(com.google.protobuf.ByteString.copyFrom(chkI))
                .build();

        int requestProtoBytes = request.getSerializedSize();
        int responseProtoBytes = -1;
        String status = "exception";

        try {
            Sign2Response response = stub.shardSign2(request);
            responseProtoBytes = response.getSerializedSize();

            if (response.getAbort()) {
                status = "abort";
                return null; // ⊥ — el trustee rechazó la firma
            }

            Round2Msg result =
                new Round2Msg(
                    response.getZT().toByteArray(),
                    response.getPathT().toByteArray()
                );

            status = "success";

            return result;
        } finally {

            emitByteMetrics(
                "grpc_client_round2",
                keyIDInt,
                status,
                requestProtoBytes,
                responseProtoBytes
            );
        }
    }

    /**
     * Emite una línea JSONL con los tamaños serializados Protobuf del RPC.
     *
     * responseProtoBytes = -1 indica que la llamada terminó con una
     * excepción antes de obtener una respuesta gRPC.
     */
    private void emitByteMetrics(
            String event,
            int keyID,
            String status,
            int requestProtoBytes,
            int responseProtoBytes
    ) {

        if (!AggregatorMetricsSink.isEnabled()) {
            return;
        }

        StringBuilder json = new StringBuilder(256);

        json.append('{');
        json.append("\"event\":\"").append(event).append('"');
        json.append(",\"timestamp_ms\":").append(System.currentTimeMillis());
        json.append(",\"trustee_address\":\"").append(address).append('"');
        json.append(",\"key_id\":").append(keyID);
        json.append(",\"status\":\"").append(status).append('"');
        json.append(",\"request_proto_bytes\":").append(requestProtoBytes);
        json.append(",\"response_proto_bytes\":").append(responseProtoBytes);

        if (responseProtoBytes >= 0) {
            json.append(",\"total_proto_bytes\":")
                    .append(
                            requestProtoBytes
                                    + responseProtoBytes
                    );
        } else {
            json.append(",\"total_proto_bytes\":-1");
        }

        json.append('}');

        AggregatorMetricsSink.emit(json.toString());
    }

    /**
     * Cierra el canal gRPC limpiamente.
     * Llamar al finalizar el proceso o cuando el proxy ya no se necesite.
     */
    public void shutdown() throws InterruptedException {
        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    public String getAddress() {
        return address;
    }
}