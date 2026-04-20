package es.uma.nicslab.hbs.util;

import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Implementación de la Función Pseudoaleatoria (PRF).
 */
public class PRF {

    // Etiquetas de separación de dominio
    public static final byte[] LABEL_R     = "R".getBytes();        // PRF^R: Share del randomizer
    public static final byte[] LABEL_CHAIN = "CHAIN".getBytes();    // PRF^CHAIN: Componentes de la matriz tridimensional de las cadenas de Winternitz
    public static final byte[] LABEL_CHK   = "CHK".getBytes();      // PRF^CHK: Share del valor de verificación CHK
    public static final byte[] LABEL_PATH  = "PATH".getBytes();     // PRF^PATH: Share de la ruta del árbol Merkle
    public static final byte[] LABEL_AUTH  = "AUTH".getBytes();     // PRF^AUTH: Valor de autenticación del randomizer

    /**
     * Evalúa la PRF. Deriva material pseudoaleatorio utilizando HKDF-Expand.
     *
     * @param key         clave privada del trustee K[t]
     * @param label       etiqueta de domain separation (LABEL_R, LABEL_CHAIN, LABEL_CHK, LABEL_PATH, LABEL_AUTH)
     * @param input       datos de entrada (KeyID, índices, etc.)
     * @param lengthBytes número de bytes de salida deseados
     * @return            bytes pseudoaleatorios derivados
     */
    public static byte[] evaluate(byte[] key, byte[] label, byte[] input, int lengthBytes) {

        // Construimos "info" concatenando label || input
        // Esto garantiza domain separation entre distintos usos de la PRF
        byte[] info = new byte[label.length + input.length];
        System.arraycopy(label, 0, info, 0, label.length);
        System.arraycopy(input, 0, info, label.length, input.length);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        // ikm = key, info = label||input
        hkdf.init(HKDFParameters.skipExtractParameters(key, info));

        byte[] output = new byte[lengthBytes];
        hkdf.generateBytes(output, 0, lengthBytes);
        return output;
    }

    /**
     * Método de conveniencia para entradas basadas en enteros.
     *
     * @param key         clave privada del trustee K[t]
     * @param label       etiqueta de domain separation (LABEL_R, LABEL_CHAIN, LABEL_CHK, LABEL_PATH, LABEL_AUTH)
     * @param inputInts   datos de entrada (KeyID, índices, etc.)
     * @param lengthBytes número de bytes de salida deseados
     * @return            bytes pseudoaleatorios derivados
     */
    public static byte[] evaluate(byte[] key, byte[] label, int[] inputInts, int lengthBytes) {
        // Serializar los ints a bytes (4 bytes cada uno, big-endian)
        byte[] input = new byte[inputInts.length * 4];
        for (int k = 0; k < inputInts.length; k++) {
            input[k*4]   = (byte)(inputInts[k] >> 24);
            input[k*4+1] = (byte)(inputInts[k] >> 16);
            input[k*4+2] = (byte)(inputInts[k] >> 8);
            input[k*4+3] = (byte)(inputInts[k]);
        }
        return evaluate(key, label, input, lengthBytes);
    }
}
