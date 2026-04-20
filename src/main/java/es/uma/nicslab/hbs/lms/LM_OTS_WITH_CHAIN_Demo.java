package es.uma.nicslab.hbs.lms;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;

public class LM_OTS_WITH_CHAIN_Demo {

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

        LMOtsChain lmOtsChain = LM_OTS_WITH_CHAIN.lms_ots_generateChain(lmOtsPrivateKey);
        byte[][][] sk = lmOtsChain.getSk();

        for (int i = 0; i < sk.length; i++)
        {
            for (int j = 0; j < sk[i].length; j++)
            {
                System.out.println("sk[" + i + "][" + j + "] = " + Hex.toHexString(sk[i][j]));
            }
        }

        LMOtsPublicKey lmOtsPublicKeyFromChain = LM_OTS_WITH_CHAIN.lms_ots_publicKeyFromChain(lmOtsPrivateKey, sk);

        boolean iguales = lmOtsPublicKey.equals(lmOtsPublicKeyFromChain);

        System.out.println("Son iguales: " + iguales);
    }

}
