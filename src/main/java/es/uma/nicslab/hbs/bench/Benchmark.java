package es.uma.nicslab.hbs.bench;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.roles.*;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.SecureRandom;
import java.util.Locale;

/**
 * Mide:
 *   1) Coste de ShardSetup (generación del CRV) por keyID, con un árbol
 *      pequeño (h=5, D=32, exacto) para distintos tamaños de coalición k.
 *      El coste para árboles grandes (h=10,15,20,25) se estima
 *      analíticamente a partir del coste medido por keyID, ya que
 *      ShardSetup escala linealmente en D.
 *   2) Coste de una firma completa (AggregatorSign: Ronda 1 + Ronda 2 +
 *      reconstrucción) y de su verificación LMS, para distintos w y k.
 *   3) Baseline: firma y verificación LMS "normal" (sin threshold), para
 *      cuantificar el overhead que introduce el esquema.
 */
public class Benchmark {

    private static final int WARMUP = 8;
    private static final int TRIALS = 15;

    public static void main(String[] args) throws Exception {
        benchmarkSetupCostPerKey();
        System.out.println();
        benchmarkSigningCost();
        System.out.println();
        benchmarkPlainLmsBaseline();
    }

    // ------------------------------------------------------------------
    // 1) Coste de ShardSetup por keyID (h=5, D=32 exacto)
    // ------------------------------------------------------------------
    private static void benchmarkSetupCostPerKey() {
        System.out.println("=== Coste de ShardSetup por keyID (D=32, h=5) ===");
        System.out.println("w & k & tiempo/keyID medio (ms) & desv. típica (ms) \\\\");

        int[] wValues = {1, 2, 4, 8};
        int[] kValues = {3, 5, 7, 10};
        double perKeyMsW4K3 = -1;

        for (int w : wValues) {
            LMOtsParameters ots = otsParamsForW(w);
            for (int k : kValues) {
                LMSParameters lmsParams = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, ots);
                int D = 1 << lmsParams.getLMSigParam().getH();
                int[][] CL = fullCoalitionCL(D, k);

                for (int i = 0; i < WARMUP; i++) {
                    new Dealer().ShardSetup(k, CL, lmsParams);
                }

                long[] times = new long[TRIALS];
                for (int i = 0; i < TRIALS; i++) {
                    long t0 = System.nanoTime();
                    new Dealer().ShardSetup(k, CL, lmsParams);
                    times[i] = System.nanoTime() - t0;
                }

                double meanMs = mean(times) / 1_000_000.0;
                double stddevMs = stddev(times) / 1_000_000.0;
                double perKeyMs = meanMs / D;
                double perKeyStddevMs = stddevMs / D;

                if (w == 4 && k == 3) {
                    perKeyMsW4K3 = perKeyMs;
                }

                System.out.printf(Locale.US, "%d & %d & %.4f & %.4f \\\\%n", w, k, perKeyMs, perKeyStddevMs);
            }
        }

        System.out.println();
        System.out.println("Extrapolación analítica (a partir del coste/keyID medido arriba, w=4, k=3):");
        System.out.println("h & D=2^h & tiempo estimado \\\\");
        for (int h : new int[]{5, 10, 15, 20, 25}) {
            long D = 1L << h;
            double estimatedMs = perKeyMsW4K3 * D;
            System.out.printf(Locale.US, "%d & %d & %s \\\\%n", h, D, humanTime(estimatedMs));
        }
    }

    // ------------------------------------------------------------------
    // 2) Coste de una firma completa (Ronda 1 + Ronda 2 + reconstrucción) y su verificación
    // ------------------------------------------------------------------
    private static void benchmarkSigningCost() throws Exception {
        System.out.println("=== Coste de AggregatorSign + verificación (D=32, h=5) ===");
        System.out.println("w & k & firma media (ms) & desv. (ms) & verif. media (ms) & desv. (ms) \\\\");

        int[] wValues = {1, 2, 4, 8};
        int[] kValues = {3, 5, 7, 10};

        for (int w : wValues) {
            LMOtsParameters ots = otsParamsForW(w);
            for (int k : kValues) {
                LMSParameters lmsParams = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, ots);
                int D = 1 << lmsParams.getLMSigParam().getH();
                int[][] CL = fullCoalitionCL(D, k);

                Dealer dealer = new Dealer();
                SetupDealer setup = dealer.ShardSetup(k, CL, lmsParams);
                PublicBulletinBoard board = setup.getBoard();
                Trustee[] trustees = setup.getTrustees();
                for (int t = 0; t < k; t++) {
                    trustees[t].TrusteeSetup(t, CL);
                }
                Aggregator aggregator = new Aggregator(board);

                int neededKeyIDs = WARMUP + TRIALS;
                if (neededKeyIDs > D) {
                    throw new IllegalStateException(
                            "D=" + D + " no alcanza para " + neededKeyIDs + " intentos (uno por keyID, one-time)");
                }

                LMSSigner signer = new LMSSigner();
                signer.init(false, board.getPublicKey());

                int keyID = 0;
                for (int i = 0; i < WARMUP; i++) {
                    aggregator.AggregatorSign(("warmup " + keyID).getBytes(), keyID);
                    keyID++;
                }

                long[] signTimes = new long[TRIALS];
                long[] verifyTimes = new long[TRIALS];

                for (int i = 0; i < TRIALS; i++) {
                    byte[] message = ("mensaje " + keyID).getBytes();

                    long t0 = System.nanoTime();
                    ThresholdSignature sig = aggregator.AggregatorSign(message, keyID);
                    signTimes[i] = System.nanoTime() - t0;

                    byte[] sigBytes = LMSSerializer.serialize(sig, board, keyID);
                    long t1 = System.nanoTime();
                    boolean ok = signer.verifySignature(message, sigBytes);
                    verifyTimes[i] = System.nanoTime() - t1;

                    if (!ok) {
                        throw new IllegalStateException("firma no verificada en el benchmark, revisa el setup");
                    }
                    keyID++;
                }

                double meanSignMs = mean(signTimes) / 1_000_000.0;
                double stddevSignMs = stddev(signTimes) / 1_000_000.0;
                double meanVerifyMs = mean(verifyTimes) / 1_000_000.0;
                double stddevVerifyMs = stddev(verifyTimes) / 1_000_000.0;

                System.out.printf(Locale.US, "%d & %d & %.3f & %.3f & %.3f & %.3f \\\\%n",
                        w, k, meanSignMs, stddevSignMs, meanVerifyMs, stddevVerifyMs);
            }
        }
    }

    // ------------------------------------------------------------------
    // 3) Baseline: LMS "normal" (single-signer, sin threshold)
    // ------------------------------------------------------------------
    private static void benchmarkPlainLmsBaseline() throws Exception {
        System.out.println("=== Baseline: firma/verificación LMS sin threshold (D=32, h=5) ===");
        System.out.println("w & firma (ms) & verificación (ms) \\\\");

        int[] wValues = {1, 2, 4, 8};

        for (int w : wValues) {
            LMOtsParameters ots = otsParamsForW(w);
            LMSParameters lmsParams = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, ots);

            SecureRandom rng = new SecureRandom();
            LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(lmsParams, rng);
            LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
            gen.init(genParams);
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

            LMSPrivateKeyParameters priv = (LMSPrivateKeyParameters) keyPair.getPrivate();
            LMSPublicKeyParameters pub = (LMSPublicKeyParameters) keyPair.getPublic();

            LMSSigner signer = new LMSSigner();
            signer.init(true, priv);
            LMSSigner verifier = new LMSSigner();
            verifier.init(false, pub);

            int trialsToRun = WARMUP + TRIALS;
            long[] signTimes = new long[TRIALS];
            long[] verifyTimes = new long[TRIALS];

            for (int i = 0; i < WARMUP; i++) {
                signer.generateSignature(("warmup " + i).getBytes());
            }

            for (int i = 0; i < TRIALS; i++) {
                byte[] message = ("mensaje " + i).getBytes();

                long t0 = System.nanoTime();
                byte[] sigBytes = signer.generateSignature(message);
                signTimes[i] = System.nanoTime() - t0;

                long t1 = System.nanoTime();
                verifier.verifySignature(message, sigBytes);
                verifyTimes[i] = System.nanoTime() - t1;
            }

            double meanSignMs = mean(signTimes) / 1_000_000.0;
            double meanVerifyMs = mean(verifyTimes) / 1_000_000.0;

            System.out.printf(Locale.US, "%d & %.3f & %.3f \\\\%n", w, meanSignMs, meanVerifyMs);
        }
    }

    // ------------------------------------------------------------------
    // Utilidades
    // ------------------------------------------------------------------

    /** Coalición de tamaño k: todos los keyIDs son firmables por los mismos k trustees {0..k-1}. */
    private static int[][] fullCoalitionCL(int D, int k) {
        int[][] CL = new int[D][];
        int[] coalition = new int[k];
        for (int i = 0; i < k; i++) coalition[i] = i;
        for (int keyID = 0; keyID < D; keyID++) {
            CL[keyID] = coalition;
        }
        return CL;
    }

    private static LMOtsParameters otsParamsForW(int w) {
        return switch (w) {
            case 1 -> LMOtsParameters.sha256_n32_w1;
            case 2 -> LMOtsParameters.sha256_n32_w2;
            case 4 -> LMOtsParameters.sha256_n32_w4;
            case 8 -> LMOtsParameters.sha256_n32_w8;
            default -> throw new IllegalArgumentException("w no soportado: " + w);
        };
    }

    private static double mean(long[] values) {
        long sum = 0;
        for (long v : values) sum += v;
        return (double) sum / values.length;
    }

    private static double stddev(long[] values) {
        double m = mean(values);
        double sumSq = 0;
        for (long v : values) {
            double d = v - m;
            sumSq += d * d;
        }
        return Math.sqrt(sumSq / values.length);
    }

    private static String humanTime(double ms) {
        if (ms < 1000) return String.format(Locale.US, "%.1f ms", ms);
        double s = ms / 1000.0;
        if (s < 60) return String.format(Locale.US, "%.1f s", s);
        double min = s / 60.0;
        if (min < 60) return String.format(Locale.US, "%.1f min", min);
        double h = min / 60.0;
        if (h < 24) return String.format(Locale.US, "%.1f h", h);
        return String.format(Locale.US, "%.1f d\u00edas", h / 24.0);
    }

}