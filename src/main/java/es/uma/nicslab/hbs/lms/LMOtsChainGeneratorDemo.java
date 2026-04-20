package es.uma.nicslab.hbs.lms;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;

public class LMOtsChainGeneratorDemo {

    public static void main(String[] args) {

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

        LMOtsPublicKey lmOtsPublicKey = LM_OTS.lms_ots_generatePublicKey(lmOtsPrivateKey);

        byte[][][] chain = LMOtsChainGenerator.lms_ots_generateChain(lmOtsPrivateKey);

        for (int i = 0; i < chain.length; i++)
        {
            for (int j = 0; j < chain[i].length; j++)
            {
                System.out.println("sk[" + i + "][" + j + "] = " + Hex.toHexString(chain[i][j]));
            }
        }

        LMOtsPublicKey lmOtsPublicKeyFromChain = LMOtsChainGenerator.lms_ots_publicKeyFromChain(lmOtsPrivateKey, chain);

        boolean iguales = lmOtsPublicKey.equals(lmOtsPublicKeyFromChain);

        System.out.println("Son iguales: " + iguales);
    }

}
