package es.uma.nicslab.hbs.metrics;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Writer asíncrono de métricas en formato JSON Lines.
 *
 * El thread que ejecuta el protocolo únicamente encola la línea.
 * La escritura a disco se realiza en un thread daemon independiente.
 *
 * Si la variable de entorno indicada no está definida, el writer queda
 * deshabilitado y emit() es un no-op.
 */
public final class AsyncJsonlMetricsWriter implements AutoCloseable {

    private static final String POISON = "\u0000KLL_METRICS_CLOSE\u0000";

    private final boolean enabled;
    private final BlockingQueue<String> queue;
    private final BufferedWriter writer;
    private final Thread worker;

    private volatile boolean closed;

    private AsyncJsonlMetricsWriter() {
        this.enabled = false;
        this.queue = null;
        this.writer = null;
        this.worker = null;
    }

    private AsyncJsonlMetricsWriter(Path path) throws IOException {
        this.enabled = true;
        this.queue = new LinkedBlockingQueue<>();

        Path absolutePath = path.toAbsolutePath();
        Path parent = absolutePath.getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        this.writer = Files.newBufferedWriter(
                absolutePath,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        );

        this.worker = new Thread(
                this::writeLoop,
                "kll-metrics-writer"
        );

        this.worker.setDaemon(true);
        this.worker.start();
    }

    /**
     * Construye un writer a partir de una variable de entorno que contiene
     * la ruta del fichero JSONL.
     */
    public static AsyncJsonlMetricsWriter fromEnvironment(String envName) {
        String value = System.getenv(envName);

        if (value == null || value.isBlank()) {
            return new AsyncJsonlMetricsWriter();
        }

        try {
            AsyncJsonlMetricsWriter writer =
                    new AsyncJsonlMetricsWriter(Path.of(value.trim()));

            Runtime.getRuntime().addShutdownHook(
                    new Thread(writer::close, "kll-metrics-shutdown")
            );

            return writer;

        } catch (IOException e) {
            throw new IllegalStateException(
                    "No se puede abrir el fichero de métricas definido por "
                            + envName + "=" + value,
                    e
            );
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Encola una línea JSONL sin realizar I/O de disco en el thread llamante.
     */
    public void emit(String jsonLine) {
        if (!enabled || closed) {
            return;
        }

        queue.offer(jsonLine);
    }

    private void writeLoop() {
        try {
            while (true) {
                String line = queue.take();

                if (POISON.equals(line)) {
                    break;
                }

                writer.write(line);
                writer.newLine();

                // Queremos preservar cada muestra incluso si el proceso
                // termina poco después.
                writer.flush();
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

        } catch (IOException e) {
            System.err.println(
                    "ERROR escribiendo métricas KLL: " + e.getMessage()
            );

        } finally {
            try {
                writer.close();
            } catch (IOException ignored) {
                // El proceso ya está terminando.
            }
        }
    }

    @Override
    public synchronized void close() {
        if (!enabled || closed) {
            return;
        }

        closed = true;
        queue.offer(POISON);

        try {
            worker.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}