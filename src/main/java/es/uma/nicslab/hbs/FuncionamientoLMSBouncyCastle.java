package es.uma.nicslab.hbs;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import java.security.SecureRandom;

import es.uma.nicslab.hbs.lms.*;

public class FuncionamientoLMSBouncyCastle {

    public static void main(String[] args) {

        System.out.println("Generando keypair LMS con Bouncy Castle...");

        // Generar keypair LMS estándar
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h10,
                        LMOtsParameters.sha256_n32_w4),
                new SecureRandom()
        );

        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        LMSPrivateKeyParameters privateKey = (LMSPrivateKeyParameters) keyPair.getPrivate();
        LMSPublicKeyParameters publicKey   = (LMSPublicKeyParameters)  keyPair.getPublic();

        // Firmar un mensaje
        System.out.println("Mensaje a firmar: Hola mundo threshold HBS");
        byte[] message = "Hola mundo lms HBS".getBytes();
        LMSSigner signer = new LMSSigner();
        signer.init(true, privateKey); // true = modo firma
        byte[] signature = signer.generateSignature(message);

        // Verificar con Bouncy Castle
        signer.init(false, publicKey); // false = modo verificación
        boolean valid = signer.verifySignature(message, signature);

        System.out.println("Firma válida: " + valid);
        System.out.println(privateKey.getIndex());
        System.out.println("Tamaño de firma: " + signature.length + " bytes");

        // Firmar un mensaje
        System.out.println("Mensaje a firmar: Hola mundo threshold HBS");
        message = "Hola mundo lms HBS".getBytes();
        signer = new LMSSigner();
        signer.init(true, privateKey); // true = modo firma
        signature = signer.generateSignature(message);

        // Verificar con Bouncy Castle
        signer.init(false, publicKey); // false = modo verificación
        valid = signer.verifySignature(message, signature);

        System.out.println("Firma válida: " + valid);
        System.out.println(privateKey.getIndex());
        System.out.println("Tamaño de firma: " + signature.length + " bytes");
    }
}
