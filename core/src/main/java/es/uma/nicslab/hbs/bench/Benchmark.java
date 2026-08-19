package es.uma.nicslab.hbs.bench;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.SetupDealer;
import es.uma.nicslab.hbs.model.ThresholdSignature;
import es.uma.nicslab.hbs.protocol.InMemoryCAS;
import es.uma.nicslab.hbs.protocol.InMemoryTrusteeState;
import es.uma.nicslab.hbs.protocol.LocalTrusteeProxy;
import es.uma.nicslab.hbs.protocol.TrusteeProxy;
import es.uma.nicslab.hbs.roles.Aggregator;
import es.uma.nicslab.hbs.roles.Dealer;
import es.uma.nicslab.hbs.roles.Trustee;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Local in-process benchmark used to characterize the cryptographic cost
 * of the KLL/Haystack implementation independently of network effects.
 *
 * Measures:
 *
 *  1. Dealer setup cost per KeyID for h=5 (D=32), varying Winternitz
 *     parameter w and coalition size k. Larger LMS trees are estimated
 *     analytically from the measured per-KeyID setup cost.
 *
 *  2. Complete local threshold signing and LMS verification.
 *
 *  3. Plain single-signer LMS signing and verification as a baseline.
 *
 * The full run preserves the methodology of the original local benchmark:
 * 8 warm-up iterations and 15 measured repetitions.
 *
 * This benchmark intentionally uses Aggregator.kkAggregatorSign(), the
 * sequential in-process reference path. The distributed implementation
 * evaluated under neteval/ uses Aggregator.aggregatorSign(), where Trustee
 * RPCs are executed in parallel within each protocol round.
 *
 * Use --smoke for a short functional check of the benchmark harness.
 */
public final class Benchmark {

    private static final int FULL_WARMUP = 8;
    private static final int FULL_TRIALS = 15;

    private final int warmup;
    private final int trials;
    private final int[] wValues;
    private final int[] kValues;
    private final boolean smoke;

    private Benchmark(boolean smoke) {
        this.smoke = smoke;

        if (smoke) {
            this.warmup = 1;
            this.trials = 2;
            this.wValues = new int[]{4};
            this.kValues = new int[]{3};
        } else {
            this.warmup = FULL_WARMUP;
            this.trials = FULL_TRIALS;
            this.wValues = new int[]{1, 2, 4, 8};
            this.kValues = new int[]{3, 5, 7, 10};
        }
    }

    public static void main(String[] args) throws Exception {
        boolean smoke = args.length == 1 && "--smoke".equals(args[0]);

        if (args.length > 0 && !smoke) {
            throw new IllegalArgumentException(
                    "Usage: Benchmark [--smoke]"
            );
        }

        Benchmark benchmark = new Benchmark(smoke);

        benchmark.printMetadata();
        benchmark.benchmarkSetupCostPerKey();
        System.out.println();
        benchmark.benchmarkSigningCost();
        System.out.println();
        benchmark.benchmarkPlainLmsBaseline();
    }

    private void printMetadata() {
        System.out.println("=== Benchmark metadata ===");
        System.out.println("Mode: " + (smoke ? "smoke" : "full"));
        System.out.println("Java: " + System.getProperty("java.version"));
        System.out.println("OS: "
                + System.getProperty("os.name") + " "
                + System.getProperty("os.version") + " "
                + System.getProperty("os.arch"));
        System.out.println("Available processors: "
                + Runtime.getRuntime().availableProcessors());
        System.out.println("Warm-up iterations: " + warmup);
        System.out.println("Measured repetitions: " + trials);
        System.out.println("==========================");
        System.out.println();
    }

    // ------------------------------------------------------------------
    // 1. Dealer setup cost per KeyID (h=5, D=32)
    // ------------------------------------------------------------------

    private void benchmarkSetupCostPerKey() throws Exception {
        System.out.println(
                "=== Dealer setup cost per KeyID (D=32, h=5) ==="
        );
        System.out.println(
                "w & k & mean time/keyID (ms) & std. dev. (ms) \\\\"
        );

        double perKeyMsW4K3 = -1.0;

        for (int w : wValues) {
            LMOtsParameters ots = otsParamsForW(w);

            for (int k : kValues) {
                LMSParameters lmsParams = new LMSParameters(
                        LMSigParameters.lms_sha256_n32_h5,
                        ots
                );

                int D = 1 << lmsParams.getLMSigParam().getH();
                int[][] coalitions = fullCoalitionCL(D, k);

                for (int i = 0; i < warmup; i++) {
                    runSetup(k, coalitions, lmsParams);
                }

                long[] times = new long[trials];

                for (int i = 0; i < trials; i++) {
                    long t0 = System.nanoTime();

                    runSetup(k, coalitions, lmsParams);

                    times[i] = System.nanoTime() - t0;
                }

                double meanMs = mean(times) / 1_000_000.0;
                double stddevMs = stddev(times) / 1_000_000.0;

                double perKeyMs = meanMs / D;
                double perKeyStddevMs = stddevMs / D;

                if (w == 4 && k == 3) {
                    perKeyMsW4K3 = perKeyMs;
                }

                System.out.printf(
                        Locale.US,
                        "%d & %d & %.4f & %.4f \\\\%n",
                        w,
                        k,
                        perKeyMs,
                        perKeyStddevMs
                );
            }
        }

        /*
         * The full benchmark always includes w=4,k=3.
         * Smoke mode also uses exactly that configuration.
         */
        if (perKeyMsW4K3 <= 0) {
            throw new IllegalStateException(
                    "Missing w=4,k=3 setup measurement"
            );
        }

        System.out.println();
        System.out.println(
                "Analytical extrapolation from measured w=4, k=3 cost:"
        );
        System.out.println("h & D=2^h & estimated time \\\\");

        for (int h : new int[]{5, 10, 15, 20, 25}) {
            long D = 1L << h;
            double estimatedMs = perKeyMsW4K3 * D;

            System.out.printf(
                    Locale.US,
                    "%d & %d & %s \\\\%n",
                    h,
                    D,
                    humanTime(estimatedMs)
            );
        }
    }

    private static void runSetup(
            int k,
            int[][] coalitions,
            LMSParameters parameters
    ) throws Exception {
        InMemoryCAS cas = new InMemoryCAS();
        Dealer dealer = new Dealer(cas);
        dealer.setup(k, coalitions, parameters);
    }

    // ------------------------------------------------------------------
    // 2. Local threshold signing + LMS verification
    // ------------------------------------------------------------------

    private void benchmarkSigningCost() throws Exception {
        System.out.println(
                "=== Local threshold signing + verification (D=32, h=5) ==="
        );
        System.out.println(
                "w & k & mean sign (ms) & std. dev. (ms) "
                        + "& mean verify (ms) & std. dev. (ms) \\\\"
        );

        for (int w : wValues) {
            LMOtsParameters ots = otsParamsForW(w);

            for (int k : kValues) {
                LMSParameters lmsParams = new LMSParameters(
                        LMSigParameters.lms_sha256_n32_h5,
                        ots
                );

                int D = 1 << lmsParams.getLMSigParam().getH();

                if (warmup + trials > D) {
                    throw new IllegalStateException(
                            "D=" + D + " is insufficient for "
                                    + (warmup + trials)
                                    + " one-time signing attempts"
                    );
                }

                int[][] coalitions = fullCoalitionCL(D, k);

                InMemoryCAS cas = new InMemoryCAS();
                Dealer dealer = new Dealer(cas);

                SetupDealer setup = dealer.setup(
                        k,
                        coalitions,
                        lmsParams
                );

                TrusteeProxy[] proxies = createLocalTrustees(
                        k,
                        setup
                );

                Aggregator aggregator = new Aggregator(
                        setup.getLmsPublicKey(),
                        cas,
                        setup.getClCid()
                );

                LMSSigner verifier = new LMSSigner();
                verifier.init(false, setup.getLmsPublicKey());

                int keyID = 0;

                for (int i = 0; i < warmup; i++) {
                    byte[] message = (
                            "warmup " + keyID
                    ).getBytes(StandardCharsets.UTF_8);

                    ThresholdSignature sig = aggregator.kkAggregatorSign(
                            message,
                            intToBytes(keyID),
                            proxies
                    );

                    if (sig == null) {
                        throw new IllegalStateException(
                                "Warm-up signature failed for keyID=" + keyID
                        );
                    }

                    keyID++;
                }

                long[] signTimes = new long[trials];
                long[] verifyTimes = new long[trials];

                for (int i = 0; i < trials; i++) {
                    byte[] message = (
                            "message " + keyID
                    ).getBytes(StandardCharsets.UTF_8);

                    long t0 = System.nanoTime();

                    ThresholdSignature sig = aggregator.kkAggregatorSign(
                            message,
                            intToBytes(keyID),
                            proxies
                    );

                    signTimes[i] = System.nanoTime() - t0;

                    if (sig == null) {
                        throw new IllegalStateException(
                                "Threshold signing failed for keyID=" + keyID
                        );
                    }

                    byte[] sigBytes = LMSSerializer.serialize(
                            sig,
                            keyID,
                            setup.getLmsPublicKey()
                    );

                    long t1 = System.nanoTime();

                    boolean ok = verifier.verifySignature(
                            message,
                            sigBytes
                    );

                    verifyTimes[i] = System.nanoTime() - t1;

                    if (!ok) {
                        throw new IllegalStateException(
                                "Generated threshold signature did not verify "
                                        + "for keyID=" + keyID
                        );
                    }

                    keyID++;
                }

                System.out.printf(
                        Locale.US,
                        "%d & %d & %.3f & %.3f & %.3f & %.3f \\\\%n",
                        w,
                        k,
                        mean(signTimes) / 1_000_000.0,
                        stddev(signTimes) / 1_000_000.0,
                        mean(verifyTimes) / 1_000_000.0,
                        stddev(verifyTimes) / 1_000_000.0
                );
            }
        }
    }

    private static TrusteeProxy[] createLocalTrustees(
            int k,
            SetupDealer setup
    ) throws Exception {
        TrusteeProxy[] proxies = new TrusteeProxy[k];

        for (int i = 0; i < k; i++) {
            Trustee trustee = new Trustee(
                    setup.getK()[i],
                    setup.getLmsPublicKey().getOtsParameters(),
                    setup.getLmsPublicKey().getI(),
                    setup.getLengthCHK(),
                    setup.getLengthPath(),
                    new InMemoryTrusteeState()
            );

            trustee.setup(i, setup.getCl());

            proxies[i] = new LocalTrusteeProxy(trustee);
        }

        return proxies;
    }

    // ------------------------------------------------------------------
    // 3. Plain LMS baseline
    // ------------------------------------------------------------------

    private void benchmarkPlainLmsBaseline() throws Exception {
        System.out.println(
                "=== Plain LMS signing/verification baseline (D=32, h=5) ==="
        );
        System.out.println(
                "w & mean sign (ms) & mean verification (ms) \\\\"
        );

        for (int w : wValues) {
            LMOtsParameters ots = otsParamsForW(w);

            LMSParameters lmsParams = new LMSParameters(
                    LMSigParameters.lms_sha256_n32_h5,
                    ots
            );

            SecureRandom rng = new SecureRandom();

            LMSKeyGenerationParameters genParams =
                    new LMSKeyGenerationParameters(lmsParams, rng);

            LMSKeyPairGenerator generator =
                    new LMSKeyPairGenerator();

            generator.init(genParams);

            AsymmetricCipherKeyPair keyPair =
                    generator.generateKeyPair();

            LMSPrivateKeyParameters privateKey =
                    (LMSPrivateKeyParameters) keyPair.getPrivate();

            LMSPublicKeyParameters publicKey =
                    (LMSPublicKeyParameters) keyPair.getPublic();

            LMSSigner signer = new LMSSigner();
            signer.init(true, privateKey);

            LMSSigner verifier = new LMSSigner();
            verifier.init(false, publicKey);

            for (int i = 0; i < warmup; i++) {
                signer.generateSignature(
                        ("warmup " + i)
                                .getBytes(StandardCharsets.UTF_8)
                );
            }

            long[] signTimes = new long[trials];
            long[] verifyTimes = new long[trials];

            for (int i = 0; i < trials; i++) {
                byte[] message = (
                        "message " + i
                ).getBytes(StandardCharsets.UTF_8);

                long t0 = System.nanoTime();

                byte[] sigBytes = signer.generateSignature(message);

                signTimes[i] = System.nanoTime() - t0;

                long t1 = System.nanoTime();

                boolean ok = verifier.verifySignature(
                        message,
                        sigBytes
                );

                verifyTimes[i] = System.nanoTime() - t1;

                if (!ok) {
                    throw new IllegalStateException(
                            "Plain LMS signature verification failed"
                    );
                }
            }

            System.out.printf(
                    Locale.US,
                    "%d & %.3f & %.3f \\\\%n",
                    w,
                    mean(signTimes) / 1_000_000.0,
                    mean(verifyTimes) / 1_000_000.0
            );
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static int[][] fullCoalitionCL(int D, int k) {
        int[][] coalitions = new int[D][];

        for (int keyID = 0; keyID < D; keyID++) {
            int[] coalition = new int[k];

            for (int i = 0; i < k; i++) {
                coalition[i] = i;
            }

            coalitions[keyID] = coalition;
        }

        return coalitions;
    }

    private static LMOtsParameters otsParamsForW(int w) {
        return switch (w) {
            case 1 -> LMOtsParameters.sha256_n32_w1;
            case 2 -> LMOtsParameters.sha256_n32_w2;
            case 4 -> LMOtsParameters.sha256_n32_w4;
            case 8 -> LMOtsParameters.sha256_n32_w8;
            default -> throw new IllegalArgumentException(
                    "Unsupported Winternitz parameter w=" + w
            );
        };
    }

    private static byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }

    private static double mean(long[] values) {
        long sum = 0;

        for (long value : values) {
            sum += value;
        }

        return (double) sum / values.length;
    }

    private static double stddev(long[] values) {
        double mean = mean(values);
        double sumSquared = 0.0;

        for (long value : values) {
            double delta = value - mean;
            sumSquared += delta * delta;
        }

        return Math.sqrt(sumSquared / values.length);
    }

    private static String humanTime(double ms) {
        if (ms < 1_000) {
            return String.format(Locale.US, "%.1f ms", ms);
        }

        double seconds = ms / 1_000.0;

        if (seconds < 60) {
            return String.format(Locale.US, "%.1f s", seconds);
        }

        double minutes = seconds / 60.0;

        if (minutes < 60) {
            return String.format(Locale.US, "%.1f min", minutes);
        }

        double hours = minutes / 60.0;

        if (hours < 24) {
            return String.format(Locale.US, "%.1f h", hours);
        }

        return String.format(
                Locale.US,
                "%.1f days",
                hours / 24.0
        );
    }
}
