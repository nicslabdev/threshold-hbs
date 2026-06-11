package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.roles.*;

import java.util.Arrays;

public class ProtocolRunner {

    public static void main(String[] args) throws Exception {

        System.out.println("Threshold-HBS\n");

        // ── Parámetros LMS ────────────────────────────────────────────────────
        // LMS_SHA256_M32_H5  → árbol de altura 5 → 2^5 = 32 KeyIDs disponibles
        // LMOTS_SHA256_N32_W4 → cadenas Winternitz de w=4
        LMSParameters lmsParams = new LMSParameters(
                LMSigParameters.lms_sha256_n32_h5,
                LMOtsParameters.sha256_n32_w4
        );

        // ── Definición de la coalición (CL) ──────────────────────────────────
        // 3 trustees (n=3), coaliciones de tamaño 2 (k=2)
        // 32 KeyIDs en total (altura 5 → 2^5)
        // Rotamos las coaliciones: {0,1}, {1,2}, {0,2}, {0,1}, ...
        int n = 3;
        int indexLimit = 32;

        int[][] coalitions = new int[indexLimit][];
        for (int keyID = 0; keyID < indexLimit; keyID++) {
            switch (keyID % 3) {
                case 0 -> coalitions[keyID] = new int[]{0, 1};
                case 1 -> coalitions[keyID] = new int[]{1, 2};
                case 2 -> coalitions[keyID] = new int[]{0, 2};
            }
        }

        // ── CAS en memoria (sin red) ──────────────────────────────────────────
        InMemoryCAS cas = new InMemoryCAS();

        // ── Setup ─────────────────────────────────────────────────────────────
        System.out.println("[Setup] Ejecutando setup...");
        Dealer dealer = new Dealer(cas);
        SetupDealer result = dealer.setup(n, coalitions, lmsParams);

        // Crear trustees locales para simulación
        Trustee[] trustees = new Trustee[n];
        for (int i = 0; i < n; i++) {
            trustees[i] = new Trustee(
                    result.getK()[i],
                    result.getLmsPublicKey().getOtsParameters(),
                    result.getLmsPublicKey().getI(),
                    result.getLengthCHK(),
                    result.getLengthPath(),
                    new InMemoryTrusteeState()
            );
            trustees[i].setup(i, result.getCl());
        }

        // Envolver en LocalTrusteeProxy
        TrusteeProxy[] proxies = Arrays.stream(trustees)
                .map(LocalTrusteeProxy::new)
                .toArray(TrusteeProxy[]::new);

        System.out.println("[Setup] Completado. Trustees: " + n + ", KeyIDs disponibles: " + indexLimit);
        for (int t = 0; t < n; t++) {
            System.out.println("  Trustee " + t + " → coaliciones: " + coalitionsOf(t, coalitions));
        }

        // ── Aggregator ────────────────────────────────────────────────────────
        Aggregator aggregator = new Aggregator(
                result.getLmsPublicKey(),
                cas,
                result.getClCid()
        );

        // ── Firma con distintas coaliciones ───────────────────────────────────
        byte[][] messages = {
                "Hola mundo threshold".getBytes(),
                "Segundo mensaje firmado por {1,2}".getBytes(),
                "Tercer mensaje firmado por {0,2}".getBytes()
        };

        boolean allOk = true;

        for (int keyID = 0; keyID < messages.length; keyID++) {

            int[] coalition = coalitions[keyID];
            System.out.printf("%n[KeyID=%d] Coalición: {%s} — Mensaje: \"%s\"%n",
                    keyID, coalitionStr(coalition), new String(messages[keyID]));

            ThresholdSignature sig = aggregator.aggregatorSign(messages[keyID], keyID, proxies);

            if (sig == null) {
                System.out.println("  ✗ aggregatorSign devolvió ⊥");
                allOk = false;
                continue;
            }

            boolean valid = verifySignature(result.getLmsPublicKey(), sig, messages[keyID], keyID);

            if (valid) {
                System.out.println("  ✓ Firma verificada correctamente (indistinguible de LMS estándar)");
            } else {
                System.out.println("  ✗ Verificación FALLIDA");
                allOk = false;
            }
        }

        // ── Prueba de protección one-time ─────────────────────────────────────
        System.out.println("\n[One-Time] Intentando reusar KeyID=0 (debe devolver ⊥)...");
        ThresholdSignature reuse = aggregator.aggregatorSign(
                "reuse attack".getBytes(), 0, proxies);
        if (reuse == null) {
            System.out.println("  ✓ Reutilización rechazada correctamente (⊥)");
        } else {
            System.out.println("  ✗ ERROR: reutilización no fue rechazada");
            allOk = false;
        }

        // ── Resultado final ───────────────────────────────────────────────────
        System.out.println("\n=== Resultado: " +
                (allOk ? "TODOS LOS TESTS PASARON ✓" : "ALGÚN TEST FALLÓ ✗") +
                " ===");
    }

    // -------------------------------------------------------------------------
    // Auxiliares
    // -------------------------------------------------------------------------

    /**
     * Verifica la ThresholdSignature contra la clave pública LMS del setup.
     * Serializa la firma al formato RFC 8554 y usa el verificador de Bouncy Castle.
     */
    private static boolean verifySignature(LMSPublicKeyParameters pub, ThresholdSignature sig, byte[] message, int keyID) {
        try {
            byte[] sigBytes = LMSSerializer.serialize(sig, keyID, pub);
            LMSSigner signer = new LMSSigner();
            signer.init(false, pub);
            return signer.verifySignature(message, sigBytes);
        } catch (Exception e) {
            System.out.println("  [ERROR en verificación] " + e.getMessage());
            return false;
        }
    }

    /** Devuelve los keyIDs donde el trustee t participa, como string legible. */
    private static String coalitionsOf(int t, int[][] coalitions) {
        StringBuilder sb = new StringBuilder();
        for (int keyID = 0; keyID < coalitions.length; keyID++) {
            for (int member : coalitions[keyID]) {
                if (member == t) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append("KeyID=").append(keyID);
                    break;
                }
            }
        }
        return sb.toString();
    }

    /** Formatea un array de índices como "0, 1". */
    private static String coalitionStr(int[] C) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < C.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(C[i]);
        }
        return sb.toString();
    }
}