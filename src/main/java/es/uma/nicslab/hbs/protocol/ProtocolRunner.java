package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.roles.*;
import es.uma.nicslab.hbs.util.ByteUtils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.SecureRandom;

public class ProtocolRunner {

    public static void main(String[] args) throws Exception {

        SecureRandom rng = new SecureRandom();
        int k = 2;
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
        int n = otsParameters.getN();
        int keyId = 0;
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

        SetupResult setupResult = Dealer.KK_Setup(keys, keyId, SK, R, PATH);
        CRV crv = setupResult.getCRV();

        System.out.println("\nCRV generado:");
        System.out.println("  " + crv.toString());

        // ── 7. Construir trustees y Aggregator ───────────────────────────────
        Trustee[] trustees = new Trustee[k];
        for (int t = 0; t < k; t++) {
            trustees[t] = new Trustee(otsParameters, I);
            trustees[t].loadShare(setupResult.getShares()[t]);
        }

        Aggregator aggregator = new Aggregator(otsParameters, I);

        // ── 8. Protocolo threshold ────────────────────────────────────────────
        ThresholdSignature thresholdSig =
                aggregator.KK_Aggregator_Sign(message, keyIdBytes, crv, trustees);

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
        System.out.println("\nFirma threshold válida (BC): " + thresholdValid);
    }
}