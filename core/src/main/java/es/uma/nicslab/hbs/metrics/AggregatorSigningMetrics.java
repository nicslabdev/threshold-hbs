package es.uma.nicslab.hbs.metrics;

/**
 * Métricas temporales de una ejecución de Aggregator.aggregatorSign().
 *
 * Todas las duraciones y offsets están expresados en nanosegundos y
 * se obtienen con System.nanoTime().
 *
 * Los offsets de RPC son relativos al inicio de aggregatorSign().
 */
public record AggregatorSigningMetrics(
        int keyID,
        int coalitionSize,
        int[] trusteeIndices,
        String status,

        long totalNs,
        long clNs,
        long crvNs,

        long round1Ns,
        long[] round1RpcNs,
        long[] round1StartOffsetNs,
        long[] round1EndOffsetNs,

        long betweenRoundsNs,

        long round2Ns,
        long[] round2RpcNs,
        long[] round2StartOffsetNs,
        long[] round2EndOffsetNs,

        long reconstructionNs
) {

    public AggregatorSigningMetrics {
        trusteeIndices = cloneOrNull(trusteeIndices);

        round1RpcNs = cloneOrNull(round1RpcNs);
        round1StartOffsetNs = cloneOrNull(round1StartOffsetNs);
        round1EndOffsetNs = cloneOrNull(round1EndOffsetNs);

        round2RpcNs = cloneOrNull(round2RpcNs);
        round2StartOffsetNs = cloneOrNull(round2StartOffsetNs);
        round2EndOffsetNs = cloneOrNull(round2EndOffsetNs);
    }

    private static int[] cloneOrNull(int[] values) {
        return values == null ? null : values.clone();
    }

    private static long[] cloneOrNull(long[] values) {
        return values == null ? null : values.clone();
    }
}