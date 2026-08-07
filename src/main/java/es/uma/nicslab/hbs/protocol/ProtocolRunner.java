package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.roles.*;
import es.uma.nicslab.hbs.util.ByteUtils;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;

import java.io.FileWriter;
import java.nio.file.Files;
import java.security.SecureRandom;

public class ProtocolRunner {

    // CODIGO DE PRUEBA PARA UNA UNICA HOJA
    /*public static void main(String[] args) throws Exception {

        SecureRandom rng = new SecureRandom();
        int k = 5;
        byte[] message = "Hola mundo threshold HBS".getBytes();

        // ── 1. Generar par de claves LMS ─────────────────────────────────────
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                rng
        );
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        LMSPrivateKeyParameters lmsPrivate = (LMSPrivateKeyParameters) keyPair.getPrivate();
        LMSPublicKeyParameters lmsPublic = (LMSPublicKeyParameters) keyPair.getPublic();

        LMOtsParameters otsParameters = lmsPrivate.getOtsParameters();
        LMSigParameters lmsParameters = lmsPrivate.getSigParameters();
        byte[] I = lmsPrivate.getI();

        int keyId = lmsPrivate.getIndex();
        byte[] keyIdBytes = ByteUtils.intToBytes(keyId);

        // ── 2. Extraer otsKey ANTES de consumir q ────────────────────────────
        LMOtsPrivateKey otsKey = lmsPrivate.getCurrentOTSKey();

        // ── 3. Generar contexto — consume q, extrae C (R) y PATH ─────────────
        LMSContext context = lmsPrivate.generateLMSContext();
        byte[] R = context.getC();
        byte[][] PATH = context.getPath();

        System.out.println("R (C de BC):  " + ByteUtils.toHex(R));
        System.out.println("PATH nodos:   " + PATH.length);

        // ── 4. Extraer SK completa ────────────────────────────────────────────
        LMOtsChain chain = LM_OTS_WITH_CHAIN.lms_ots_generateChain(otsKey);
        byte[][][] SK = chain.getSK();

        System.out.println("SK cadenas:   " + SK.length);
        System.out.println("SK pasos:     " + SK[0].length);

        // ── 5. Firma de referencia LMS ────────────────────────────────────────
        context.update(message, 0, message.length);
        LMSSignature refSig = LMS.generateSign(context);
        byte[] refSigBytes = refSig.getEncoded();

        System.out.println("\nFirma referencia (" + refSigBytes.length + " bytes):");
        System.out.println(ByteUtils.toHex(refSigBytes));

        // Verificar firma de referencia con BC
        boolean refValid = LMS.verifySignature(lmsPublic, refSig, message);
        System.out.println("Firma referencia válida (BC): " + refValid);

        // ── 6. KK_Setup ──────────────────────────────────────────────────────
        byte[][] keys = new byte[k][32];
        for (int t = 0; t < k; t++) rng.nextBytes(keys[t]);

        PublicBulletinBoard board = new PublicBulletinBoard(lmsPublic, otsParameters, I);

        Dealer dealer = new Dealer(board);

        dealer.KK_Setup(keys, keyIdBytes, SK, R, PATH);
        CRV crv = board.getCRV();

        System.out.println("\nCRV generado:");
        System.out.println("  " + crv.toString());

        // ── 7. Construir trustees y Aggregator ───────────────────────────────
        Trustee[] trustees = new Trustee[k];
        for (int t = 0; t < k; t++) {
            trustees[t] = new Trustee(keys[t], board);
        }
        board.publishTrustees(trustees);

        Aggregator aggregator = new Aggregator(board);

        // ── 8. Protocolo threshold ────────────────────────────────────────────
        ThresholdSignature thresholdSig = aggregator.KK_Aggregator_Sign(message, keyIdBytes);

        if (thresholdSig == null) {
            System.out.println("\nERROR: el protocolo threshold devolvió null");
            return;
        }

        System.out.println("\nThresholdSignature generada:");
        System.out.println("  R:    " + ByteUtils.toHex(thresholdSig.getR()));
        System.out.println("  Z:    " + ByteUtils.toHex(thresholdSig.getZ()));
        System.out.println("  PATH nodos: " + thresholdSig.getPATH().length);

        // ── 9. Verificar que R coincide ───────────────────────────────────────
        System.out.println("\nR original == R threshold: " +
                ByteUtils.toHex(R).equals(ByteUtils.toHex(thresholdSig.getR())));

        // ── 10. Serializar ThresholdSignature ─────────────────────────────────
        LMSSerializer serializer = new LMSSerializer(otsParameters, lmsParameters);
        byte[] thresholdSigBytes = serializer.serialize(thresholdSig, keyId);

        System.out.println("\nFirma threshold (" + thresholdSigBytes.length + " bytes):");
        System.out.println(ByteUtils.toHex(thresholdSigBytes));

        // ── 11. Comparar byte a byte ──────────────────────────────────────────
        boolean bytesIguales = java.util.Arrays.equals(refSigBytes, thresholdSigBytes);
        System.out.println("\nFirmas idénticas byte a byte: " + bytesIguales);

        if (!bytesIguales) {
            // Encontrar primer byte distinto para debug
            int minLen = Math.min(refSigBytes.length, thresholdSigBytes.length);
            for (int i = 0; i < minLen; i++) {
                if (refSigBytes[i] != thresholdSigBytes[i]) {
                    System.out.println("Primer byte distinto en posición: " + i);
                    System.out.println("  Referencia: " + String.format("%02x", refSigBytes[i]));
                    System.out.println("  Threshold:  " + String.format("%02x", thresholdSigBytes[i]));
                    break;
                }
            }
        }

        // ── 12. Verificar firma threshold con BC ──────────────────────────────
        boolean thresholdValid = LMS.verifySignature(lmsPublic, thresholdSigBytes, message);
        System.out.println("\nFirma threshold válida (BC): " + thresholdValid + "\n");

        // Exportar clave pública en PEM (lo que OpenSSL espera con -pubin)
        exportPublicKeyToPEM(lmsPublic, "lmspubthreshold.pem");

        // 4. Exportar firma como bytes raw
        exportSignatureRaw(thresholdSigBytes, "sigthreshold.file");

        // 5. Exportar mensaje (el -in de pkeyutl)
        Files.write(java.nio.file.Paths.get("messagethreshold.bin"), message);

        System.out.println("Archivos generados: lmspubthreshold.pem, sigthreshold.file, messagethreshold.bin, cert.pem");
        System.out.println("Verificar con:");
        System.out.println("  openssl pkeyutl -verify -in messagethreshold.bin -sigfile sigthreshold.file -inkey lmspubthreshold.pem -pubin");

    } */

    /**
     * Exporta la clave pública LMS en formato PEM (SubjectPublicKeyInfo).
     * Esto es lo que JcaPEMWriter sabe manejar correctamente.
     */
    /* static void exportPublicKeyToPEM(LMSPublicKeyParameters pub, String path) throws Exception {
        // Reconstruir la clave pública de BC desde los bytes de nuestra implementación
        byte[] pubEncoded = pub.getEncoded();
        org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters bcPub = org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters.getInstance(pubEncoded);

        // Convertir a SubjectPublicKeyInfo (formato X.509 estándar)
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcPub);

        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(path))) {
            writer.writeObject(spki);
        }
        System.out.println("Clave pública exportada a: " + path);
    } */

    /**
     * La firma LMS es simplemente bytes raw según RFC 8554.
     * OpenSSL los lee directamente con -sigfile.
     * No hay encapsulamiento PEM necesario aquí.
     */
    /* static void exportSignatureRaw(byte[] signature, String path) throws Exception {
        Files.write(java.nio.file.Paths.get(path), signature);
        System.out.println("Firma exportada a: " + path);
    } */

    public static void main(String[] args) throws Exception {

        System.out.println("Threshold-HBS: Distributed Signing Protocol\n");

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

        System.out.println("[Setup] Completado. Trustees: " + n + ", KeyIDs disponibles: " + indexLimit);
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
            System.out.printf("%n[KeyID=%d] Coalición: {%s} — Mensaje: \"%s\"%n", keyID, coalitionStr(coalition), new String(messages[keyID]));

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
        System.out.println("\nResultado: " + (allOk ? "TODOS LOS TESTS PASARON ✓" : "ALGÚN TEST FALLÓ ✗"));
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