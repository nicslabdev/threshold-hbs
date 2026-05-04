package es.uma.nicslab.hbs.util;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.macs.KMAC;

public class PRF {

    // Etiquetas de separación de dominio
    public static final byte[] LABEL_R = "R".getBytes(); // PRF^R: Share del randomizer
    public static final byte[] LABEL_CHAIN = "CHAIN".getBytes(); // PRF^CHAIN: Componentes de la matriz tridimensional de las cadenas de Winternitz
    public static final byte[] LABEL_CHK = "CHK".getBytes(); // PRF^CHK: Share del valor de verificación CHK
    public static final byte[] LABEL_PATH = "PATH".getBytes(); // PRF^PATH: Share de la ruta del árbol Merkle
    public static final byte[] LABEL_AUTH = "AUTH".getBytes(); // PRF^AUTH: Valor de autenticación del randomizer

    public static byte[] evalR(byte[] key, byte[] keyId, int n) {
        return evaluate(key, LABEL_R, keyId, n);
    }

    public static byte[] evalCHAIN(byte[] key, byte[] keyId, int i, int j, int n) {
        return evaluate(key, LABEL_CHAIN, ByteUtils.concat(keyId, ByteUtils.intToBytes(i), ByteUtils.intToBytes(j)), n);
    }

    public static byte[] evalCHK(byte[] key, byte[] keyId, int n) {
        return evaluate(key, LABEL_CHK, keyId, n);
    }

    public static byte[] evalPATH(byte[] key, byte[] keyId, int n) {
        return evaluate(key, LABEL_PATH, keyId, n);
    }

    public static byte[] evalAUTH(byte[] key, byte[] keyId, byte[] R, int n) {
        return evaluate(key, LABEL_AUTH, ByteUtils.concat(keyId, R), n);
    }

    public static byte[] evaluate(byte[] key, byte[] label, byte[] input, int lengthBytes) {
        KMAC kmac = new KMAC(256, label);
        kmac.init(new KeyParameter(key));
        kmac.update(input, 0, input.length);
        byte[] output = new byte[lengthBytes];
        kmac.doFinal(output, 0, lengthBytes);

        return output;
    }

}
