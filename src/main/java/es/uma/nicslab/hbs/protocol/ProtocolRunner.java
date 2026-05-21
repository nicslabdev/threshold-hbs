package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.roles.*;

public class ProtocolRunner {

    public static void main(String[] args) {

        System.out.println("=== Threshold-HBS — Sección 4: Distributed Signing Protocol ===\n");

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
        int n = 3;  // número total de trustees
        int indexLimit = 32; // 2^h = 2^5

        int[][] CL = new int[indexLimit][];
        for (int keyID = 0; keyID < indexLimit; keyID++) {
            switch (keyID % 3) {
                case 0 -> CL[keyID] = new int[]{0, 1};
                case 1 -> CL[keyID] = new int[]{1, 2};
                case 2 -> CL[keyID] = new int[]{0, 2};
            }
        }

        // ── Setup ─────────────────────────────────────────────────────────────
        System.out.println("[Setup] Ejecutando ShardSetup...");
        Dealer dealer = new Dealer();
        SetupDealer setup = dealer.ShardSetup(n, CL, lmsParams);

        PublicBulletinBoard board = setup.getBoard();
        Trustee[] trustees = setup.getTrustees();

        // TrusteeSetup: cada trustee construye su keylist a partir de CL
        for (int t = 0; t < n; t++) {
            trustees[t].TrusteeSetup(t, CL);
        }

        System.out.println("[Setup] Completado. Trustees: " + n +
                ", KeyIDs disponibles: " + indexLimit);
        for (int t = 0; t < n; t++) {
            System.out.println("  Trustee " + t + " → coaliciones: " + coalitionsOf(t, CL));
        }

        // ── Aggregator ────────────────────────────────────────────────────────
        Aggregator aggregator = new Aggregator(board);

        // ── Firma con distintas coaliciones ───────────────────────────────────
        byte[][] messages = {
                "Hola mundo threshold".getBytes(),
                "Segundo mensaje firmado por {1,2}".getBytes(),
                "Tercer mensaje firmado por {0,2}".getBytes()
        };

        boolean allOk = true;

        for (int keyID = 0; keyID < messages.length; keyID++) {

            int[] coalition = CL[keyID];
            System.out.printf("%n[KeyID=%d] Coalición: {%s} — Mensaje: \"%s\"%n",
                    keyID, coalitionStr(coalition), new String(messages[keyID]));

            ThresholdSignature sig = aggregator.AggregatorSign(messages[keyID], keyID);

            if (sig == null) {
                System.out.println("  ✗ AggregatorSign devolvió ⊥");
                allOk = false;
                continue;
            }

            // Verificar la firma con la clave pública LMS estándar
            boolean valid = verifySignature(board, sig, messages[keyID], keyID);

            if (valid) {
                System.out.println("  ✓ Firma verificada correctamente (indistinguible de LMS estándar)");
            } else {
                System.out.println("  ✗ Verificación FALLIDA");
                allOk = false;
            }
        }

        // ── Prueba de protección one-time ─────────────────────────────────────
        System.out.println("\n[One-Time] Intentando reusar KeyID=0 (debe devolver ⊥)...");
        ThresholdSignature reuse = aggregator.AggregatorSign("reuse attack".getBytes(), 0);
        if (reuse == null) {
            System.out.println("  ✓ Reutilización rechazada correctamente (⊥)");
        } else {
            System.out.println("  ✗ ERROR: reutilización no fue rechazada");
            allOk = false;
        }

        // ── Resultado final ───────────────────────────────────────────────────
        System.out.println("\n=== Resultado: " + (allOk ? "TODOS LOS TESTS PASARON ✓" : "ALGÚN TEST FALLÓ ✗") + " ===");
    }

    /**
     * Verifica la ThresholdSignature contra la clave pública LMS del board.
     * Serializa la firma al formato RFC 8554 y usa el verificador de Bouncy Castle.
     */
    private static boolean verifySignature(PublicBulletinBoard board,
                                           ThresholdSignature sig,
                                           byte[] message,
                                           int keyID) {
        try {
            byte[] sigBytes = LMSSerializer.serialize(sig, board, keyID);
            LMSPublicKeyParameters pub = board.getPublicKey();
            LMSSigner signer = new LMSSigner();
            signer.init(false, pub);
            return signer.verifySignature(message, sigBytes);
        } catch (Exception e) {
            System.out.println("  [ERROR en verificación] " + e.getMessage());
            return false;
        }
    }

    /** Devuelve los keyIDs donde el trustee t participa, como string legible. */
    private static String coalitionsOf(int t, int[][] CL) {
        StringBuilder sb = new StringBuilder();
        for (int keyID = 0; keyID < CL.length; keyID++) {
            for (int member : CL[keyID]) {
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