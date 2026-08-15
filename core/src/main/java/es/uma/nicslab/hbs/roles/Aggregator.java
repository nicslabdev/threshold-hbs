package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.metrics.AggregatorSigningMetrics;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.CASReader;
import es.uma.nicslab.hbs.protocol.CoalitionEntry;
import es.uma.nicslab.hbs.protocol.TrusteeProxy;
import es.uma.nicslab.hbs.util.ByteUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Rol del Aggregator en el protocolo threshold HBS.
 *
 * Usa TrusteeProxy[] en lugar de Trustee[] para ser agnóstico sobre si
 * los trustees son locales (tests) o remotos via gRPC (producción).
 *
 * Las llamadas a los trustees se ejecutan en paralelo dentro de cada ronda.
 * La Round 2 solo comienza una vez completadas todas las llamadas de Round 1.
 */
public class Aggregator {

    private final LMSPublicKeyParameters lmsPublicKey;
    private final CASReader cas;
    private final String clCid;

    private final ExecutorService trusteeExecutor =
            Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "kll-trustee-rpc");
                t.setDaemon(true);
                return t;
            });

    /**
     * Métricas de la última llamada a aggregatorSign() realizada desde
     * el thread llamante.
     *
     * ThreadLocal evita que dos peticiones concurrentes al Aggregator
     * pisen entre sí sus métricas.
     */
    private final ThreadLocal<AggregatorSigningMetrics> lastMetrics = new ThreadLocal<>();

    public Aggregator(LMSPublicKeyParameters lmsPublicKey, CASReader cas, String clCid) {
        this.lmsPublicKey = lmsPublicKey;
        this.cas = cas;
        this.clCid = clCid;
    }

    /**
     * Devuelve las métricas correspondientes a la última ejecución de
     * aggregatorSign() realizada por el thread actual.
     */
    public AggregatorSigningMetrics getLastMetrics() {
        return lastMetrics.get();
    }

    public ThresholdSignature aggregatorSign(byte[] message, int keyID, TrusteeProxy[] trustees) throws Exception {
        // Evita devolver métricas antiguas si esta ejecución falla
        // antes de producir un nuevo snapshot.
        lastMetrics.remove();

        AggregatorSigningTrace trace = new AggregatorSigningTrace(keyID);

        try {
            // -----------------------------------------------------------------
            // Coalition List
            // -----------------------------------------------------------------
            long start = System.nanoTime();
            CoalitionEntry[] cl = cas.getCL(clCid);
            trace.clNs = System.nanoTime() - start;

            CoalitionEntry entry = cl[keyID];
            int[] coalition = entry.trustees();
            int k = coalition.length;
            trace.setCoalition(coalition);

            LMOtsParameters otsParams = lmsPublicKey.getOtsParameters();
            int n = otsParams.getN();
            byte[] keyIdBytes = ByteUtils.intToBytes(keyID);

            // -----------------------------------------------------------------
            // CRV
            // -----------------------------------------------------------------
            start = System.nanoTime();
            CRV crv = cas.getCRV(entry.crvCid());
            trace.crvNs = System.nanoTime() - start;

            // -----------------------------------------------------------------
            // Round 1
            // -----------------------------------------------------------------
            Round1Result round1 = executeRound1(
                    trustees, coalition, keyIdBytes, message, trace
            );

            if (!round1.success()) {
                trace.status = "abort_round1";
                return null;
            }

            // -----------------------------------------------------------------
            // Barrier + reconstruction between Round 1 and Round 2
            // -----------------------------------------------------------------
            start = System.nanoTime();

            byte[] R = ByteUtils.xorAll(crv.getR(), round1.sharesR());
            byte[] CHKConcat = ByteUtils.xorAll(crv.getCHK(), round1.sharesCHK());
            byte[][] CHK = ByteUtils.deconcat(CHKConcat, n);

            trace.betweenRoundsNs = System.nanoTime() - start;

            // -----------------------------------------------------------------
            // Round 2
            // -----------------------------------------------------------------
            Round2Result round2 = executeRound2(
                    trustees, coalition, keyIdBytes, R, CHK, trace
            );

            if (!round2.success()) {
                trace.status = "abort_round2";
                return null;
            }

            // -----------------------------------------------------------------
            // Final reconstruction
            // -----------------------------------------------------------------
            start = System.nanoTime();

            byte[] PATHConcat = ByteUtils.xorAll(crv.getPATH(), round2.sharesPATH());
            byte[][] PATH = ByteUtils.deconcat(PATHConcat, n);

            byte[] h = computeH(R, message, keyIdBytes);

            byte[] Z_CRV = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(
                    h, crv.getSK(), otsParams
            );

            byte[] Z = ByteUtils.xorAll(Z_CRV, round2.sharesZ());
            ThresholdSignature signature = new ThresholdSignature(R, PATH, Z);

            trace.reconstructionNs = System.nanoTime() - start;
            trace.status = "success";

            return signature;
        } finally {
            trace.finish();
            lastMetrics.set(trace.snapshot());
        }
    }

    /**
     * Ejecuta en paralelo Round 1 para todos los trustees de la coalición.
     *
     * Devuelve las shares necesarias para reconstruir R y CHK.
     * La ronda termina únicamente cuando se han recogido los Future
     * correspondientes a todos los trustees o se detecta un abort.
     */
    private Round1Result executeRound1(
            TrusteeProxy[] trustees,
            int[] coalition,
            byte[] keyIdBytes,
            byte[] message,
            AggregatorSigningTrace trace
    ) throws Exception {
        int k = coalition.length;
        byte[][] sharesR = new byte[k][];
        byte[][] sharesCHK = new byte[k][];
        List<Future<Round1Msg>> futures = new ArrayList<>(k);

        trace.initRound1(k);

        // El timer de ronda comienza justo antes del primer submit.
        long roundStart = System.nanoTime();

        try {
            for (int i = 0; i < k; i++) {
                final int pos = i;

                futures.add(trusteeExecutor.submit(() -> {
                    long rpcStart = System.nanoTime();
                    trace.recordRound1Start(pos, rpcStart);

                    try {
                        return callShardSign1(
                                trustees[coalition[pos]], keyIdBytes, message
                        );
                    } finally {
                        long rpcEnd = System.nanoTime();
                        trace.recordRound1End(pos, rpcStart, rpcEnd);
                    }
                }));
            }

            for (int i = 0; i < k; i++) {
                Round1Msg round1 = futures.get(i).get();

                if (round1 == null) {
                    return new Round1Result(false, sharesR, sharesCHK);
                }

                sharesR[i] = round1.getR_t();
                sharesCHK[i] = round1.getCHK_t();
            }

            return new Round1Result(true, sharesR, sharesCHK);
        } finally {
            trace.round1Ns = System.nanoTime() - roundStart;
        }
    }

    /**
     * Ejecuta en paralelo Round 2 para todos los trustees de la coalición.
     *
     * Solo se invoca después de que Round 1 haya terminado completamente
     * y se hayan reconstruido R y CHK.
     */
    private Round2Result executeRound2(
            TrusteeProxy[] trustees,
            int[] coalition,
            byte[] keyIdBytes,
            byte[] R,
            byte[][] CHK,
            AggregatorSigningTrace trace
    ) throws Exception {
        int k = coalition.length;
        byte[][] sharesPATH = new byte[k][];
        byte[][] sharesZ = new byte[k][];
        List<Future<Round2Msg>> futures = new ArrayList<>(k);

        trace.initRound2(k);

        // El timer de ronda comienza justo antes del primer submit.
        long roundStart = System.nanoTime();

        try {
            for (int i = 0; i < k; i++) {
                final int pos = i;

                futures.add(trusteeExecutor.submit(() -> {
                    long rpcStart = System.nanoTime();
                    trace.recordRound2Start(pos, rpcStart);

                    try {
                        return callShardSign2(
                                trustees[coalition[pos]], keyIdBytes, R, CHK[pos]
                        );
                    } finally {
                        long rpcEnd = System.nanoTime();
                        trace.recordRound2End(pos, rpcStart, rpcEnd);
                    }
                }));
            }

            for (int i = 0; i < k; i++) {
                Round2Msg round2 = futures.get(i).get();

                if (round2 == null) {
                    return new Round2Result(false, sharesPATH, sharesZ);
                }

                sharesPATH[i] = round2.getPATH_t();
                sharesZ[i] = round2.getZ_t();
            }

            return new Round2Result(true, sharesPATH, sharesZ);
        } finally {
            trace.round2Ns = System.nanoTime() - roundStart;
        }
    }

    public ThresholdSignature kkAggregatorSign(
            byte[] message,
            byte[] keyID,
            TrusteeProxy[] trustees
    ) throws Exception {
        CoalitionEntry[] cl = cas.getCL(clCid);
        int ID = ByteUtils.bytesToInt(keyID);
        CoalitionEntry entry = cl[ID];

        LMOtsParameters otsParams = lmsPublicKey.getOtsParameters();
        int n = otsParams.getN();
        int k = trustees.length;

        CRV crv = cas.getCRV(entry.crvCid());

        // --- Round 1 ---
        byte[][] sharesR = new byte[k][];
        byte[][] sharesCHK = new byte[k][];

        for (int i = 0; i < k; i++) {
            Round1Msg round1 = callShardSign1(trustees[i], keyID, message);

            if (round1 == null) {
                return null;
            }

            sharesR[i] = round1.getR_t();
            sharesCHK[i] = round1.getCHK_t();
        }

        byte[] R = ByteUtils.xorAll(crv.getR(), sharesR);
        byte[] CHKConcat = ByteUtils.xorAll(crv.getCHK(), sharesCHK);
        byte[][] CHK = ByteUtils.deconcat(CHKConcat, n);

        // --- Round 2 ---
        byte[][] sharesPATH = new byte[k][];
        byte[][] sharesZ = new byte[k][];

        for (int i = 0; i < k; i++) {
            Round2Msg round2 = callShardSign2(trustees[i], keyID, R, CHK[i]);

            if (round2 == null) {
                return null;
            }

            sharesPATH[i] = round2.getPATH_t();
            sharesZ[i] = round2.getZ_t();
        }

        byte[] PATHConcat = ByteUtils.xorAll(crv.getPATH(), sharesPATH);
        byte[][] PATH = ByteUtils.deconcat(PATHConcat, n);

        byte[] h = computeH(R, message, keyID);

        byte[] Z_CRV = LM_OTS_WITH_CHAIN.lm_ots_generate_ZFromSK(
                h, crv.getSK(), otsParams
        );

        byte[] Z = ByteUtils.xorAll(Z_CRV, sharesZ);

        return new ThresholdSignature(R, PATH, Z);
    }

    // -------------------------------------------------------------------------
    // Adaptadores de comunicación con TrusteeProxy
    // -------------------------------------------------------------------------

    private Round1Msg callShardSign1(
            TrusteeProxy trustee,
            byte[] keyID,
            byte[] message
    ) throws Exception {
        return trustee.shardSign1(keyID, message);
    }

    private Round2Msg callShardSign2(
            TrusteeProxy trustee,
            byte[] keyID,
            byte[] R,
            byte[] chkI
    ) throws Exception {
        return trustee.shardSign2(keyID, R, chkI);
    }

    private byte[] computeH(byte[] R, byte[] M, byte[] keyID) {
        int q = ByteUtils.bytesToInt(keyID);

        return LMSHashUtils.computeH(
                lmsPublicKey.getOtsParameters(),
                lmsPublicKey.getI(),
                q,
                R,
                M
        );
    }

    // -------------------------------------------------------------------------
    // Resultados internos de las dos rondas
    // -------------------------------------------------------------------------

    private record Round1Result(
            boolean success,
            byte[][] sharesR,
            byte[][] sharesCHK
    ) {}

    private record Round2Result(
            boolean success,
            byte[][] sharesPATH,
            byte[][] sharesZ
    ) {}

    // -------------------------------------------------------------------------
    // Trace mutable utilizado únicamente durante una firma
    // -------------------------------------------------------------------------

    private static final class AggregatorSigningTrace {

        private final int keyID;
        private final long totalStartNs;

        private int coalitionSize;
        private int[] trusteeIndices;
        private String status = "exception";

        private long totalNs = -1L;
        private long clNs = -1L;
        private long crvNs = -1L;

        private long round1Ns = -1L;
        private long[] round1RpcNs;
        private long[] round1StartOffsetNs;
        private long[] round1EndOffsetNs;

        private long betweenRoundsNs = -1L;

        private long round2Ns = -1L;
        private long[] round2RpcNs;
        private long[] round2StartOffsetNs;
        private long[] round2EndOffsetNs;

        private long reconstructionNs = -1L;

        private AggregatorSigningTrace(int keyID) {
            this.keyID = keyID;
            this.totalStartNs = System.nanoTime();
        }

        private void setCoalition(int[] coalition) {
            this.coalitionSize = coalition.length;
            this.trusteeIndices = coalition.clone();
        }

        private void initRound1(int k) {
            this.round1RpcNs = metricArray(k);
            this.round1StartOffsetNs = metricArray(k);
            this.round1EndOffsetNs = metricArray(k);
        }

        private void initRound2(int k) {
            this.round2RpcNs = metricArray(k);
            this.round2StartOffsetNs = metricArray(k);
            this.round2EndOffsetNs = metricArray(k);
        }

        private void recordRound1Start(int position, long rpcStartNs) {
            round1StartOffsetNs[position] = rpcStartNs - totalStartNs;
        }

        private void recordRound1End(int position, long rpcStartNs, long rpcEndNs) {
            round1RpcNs[position] = rpcEndNs - rpcStartNs;
            round1EndOffsetNs[position] = rpcEndNs - totalStartNs;
        }

        private void recordRound2Start(int position, long rpcStartNs) {
            round2StartOffsetNs[position] = rpcStartNs - totalStartNs;
        }

        private void recordRound2End(int position, long rpcStartNs, long rpcEndNs) {
            round2RpcNs[position] = rpcEndNs - rpcStartNs;
            round2EndOffsetNs[position] = rpcEndNs - totalStartNs;
        }

        private void finish() {
            totalNs = System.nanoTime() - totalStartNs;
        }

        private AggregatorSigningMetrics snapshot() {
            /*
             * Solo exponemos los arrays detallados de RPC cuando la firma
             * ha terminado correctamente. En un abort temprano podrían
             * existir Futures ya enviados que sigan finalizando mientras
             * aggregatorSign() retorna.
             */
            boolean complete = "success".equals(status);

            return new AggregatorSigningMetrics(
                    keyID,
                    coalitionSize,
                    trusteeIndices,
                    status,
                    totalNs,
                    clNs,
                    crvNs,
                    round1Ns,
                    complete ? round1RpcNs : null,
                    complete ? round1StartOffsetNs : null,
                    complete ? round1EndOffsetNs : null,
                    betweenRoundsNs,
                    round2Ns,
                    complete ? round2RpcNs : null,
                    complete ? round2StartOffsetNs : null,
                    complete ? round2EndOffsetNs : null,
                    reconstructionNs
            );
        }

        private static long[] metricArray(int size) {
            long[] values = new long[size];
            Arrays.fill(values, -1L);
            return values;
        }
    }
}