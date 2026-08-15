package es.uma.nicslab.hbs.aggregator;

import es.uma.nicslab.hbs.metrics.AsyncJsonlMetricsWriter;

/**
 * Sink compartido de métricas del proceso Aggregator.
 *
 * AggregatorServer y todos los GrpcTrusteeProxy escriben mediante una
 * única instancia de AsyncJsonlMetricsWriter, evitando múltiples writers
 * concurrentes sobre el mismo fichero JSONL.
 */
final class AggregatorMetricsSink {

    private static final AsyncJsonlMetricsWriter WRITER =
            AsyncJsonlMetricsWriter.fromEnvironment("KLL_METRICS_FILE");

    private AggregatorMetricsSink() {
    }

    static boolean isEnabled() {
        return WRITER.isEnabled();
    }

    static void emit(String jsonLine) {
        WRITER.emit(jsonLine);
    }
}