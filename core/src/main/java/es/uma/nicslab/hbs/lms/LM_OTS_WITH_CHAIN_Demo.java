package es.uma.nicslab.hbs.lms;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.Digest;

import java.security.SecureRandom;

public class LM_OTS_WITH_CHAIN_Demo {

    public static void main(String[] args) throws Exception{

        System.out.println("Funcionamiento de LMOtsChainGenerator...");

        // Generar keypair LMS estándar
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5,
                        LMOtsParameters.sha256_n32_w4),
                new SecureRandom()
        );

        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        LMSPrivateKeyParameters privateKey = (LMSPrivateKeyParameters) keyPair.getPrivate();

        LMOtsPrivateKey lmOtsPrivateKey = privateKey.getCurrentOTSKey();

        System.out.println("La clave privada actual es la de la posición " + privateKey.getIndex());

        LMOtsPublicKey lmOtsPublicKey = LM_OTS.lms_ots_generatePublicKey(lmOtsPrivateKey);

        LMOtsChain lmOtsChain = LM_OTS_WITH_CHAIN.lms_ots_generateChain(lmOtsPrivateKey);
        byte[][][] SK = lmOtsChain.getSK();
        LMOtsParameters parameter = lmOtsChain.getParameter();

        /*for (int i = 0; i < SK.length; i++)
        {
            for (int j = 0; j < SK[i].length; j++)
            {
                System.out.println("SK[" + i + "][" + j + "] = " + Hex.toHexString(SK[i][j]));
            }
        }*/

        LMOtsPublicKey lmOtsPublicKeyFromChain = LM_OTS_WITH_CHAIN.lms_ots_publicKeyFromChain(lmOtsChain);

        boolean iguales = lmOtsPublicKey.equals(lmOtsPublicKeyFromChain);
        System.out.println("Son iguales: " + iguales);

        byte[] mensaje = SecureRandom.getSeed(32);
        System.out.println("Mensaje a firmar: " + Hex.toHexString(mensaje));

        // DigestUtil.getDigest() devuelve el Digest asociado al parámetro LMS
        Digest digest = DigestUtil.getDigest(LMSigParameters.lms_sha256_n32_h5);
        digest.update(mensaje, 0, mensaje.length);
        byte[] mensajeHasheado = new byte[digest.getDigestSize()]; // 32 bytes para SHA-256
        digest.doFinal(mensajeHasheado, 0);

        LMSigParameters parameterSignature = LMSigParameters.lms_sha256_n32_h5;
        byte[] C = new byte[parameter.getN()];

        LMOtsSignature signature = LM_OTS.lm_ots_generate_signature(parameterSignature, lmOtsPrivateKey, new byte[1][1], mensaje, true);
        LMOtsSignature signatureWithChain = LM_OTS_WITH_CHAIN.lm_ots_generate_signatureFromChain(lmOtsChain, mensaje, C);

        System.out.println("Firma 1: " + Hex.toHexString(signature.getEncoded()));
        System.out.println("Firma 2: " + Hex.toHexString(signatureWithChain.getEncoded()));
        System.out.println("Son iguales: " + signature.equals(signatureWithChain));

        boolean verificado = LM_OTS.lm_ots_validate_signature(lmOtsPublicKey, signature, mensaje, true);
        boolean verificadoChain = LM_OTS.lm_ots_validate_signature(lmOtsPublicKey, signatureWithChain, mensaje, true);

        System.out.println("Verificación estándar de la firma estándar: " +  verificado);
        System.out.println("Verificación estándar de la firma hecha con la cadena de hashes: " +  verificadoChain);

        System.out.println("///////////////////////////////////////////////////////////");

        lmOtsPrivateKey = privateKey.getNextOtsPrivateKey();
        lmOtsPublicKey = LM_OTS.lms_ots_generatePublicKey(lmOtsPrivateKey);

        System.out.println("La clave privada actual es la de la posición " + privateKey.getIndex());

        mensaje = SecureRandom.getSeed(32);
        System.out.println("Mensaje a firmar: " + Hex.toHexString(mensaje));

        LMSigParameters parameterSignature2 = LMSigParameters.lms_sha256_n32_h5;
        byte[][] path = new byte[1][1]; // Esto es de prueba, obviamente no es un camino válido

        signature = LM_OTS.lm_ots_generate_signature(parameterSignature2, lmOtsPrivateKey, path, mensaje, false);
        System.out.println("Firma: " + Hex.toHexString(signature.getEncoded()));

        verificado = LM_OTS.lm_ots_validate_signature(lmOtsPublicKey, signature, mensaje, false);
        System.out.println("Verificación: " +  verificado);

    }

}
