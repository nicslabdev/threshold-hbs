package es.uma.nicslab.hbs.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Pack;

public class LMOtsChainGenerator {

    // Constante de dominio para la generación de clave pública (domain separation)
    private static final short D_PBLC = (short)0x8080;

    // Índices que indican en qué posición del buffer se escriben ciertos campos
    private static final int ITER_K = 20; // Indice i
    private static final int ITER_PREV = 23; // Resultado del hash previo
    private static final int ITER_J = 22; // Contador j

    public static byte[][][] lms_ots_generateChain(LMOtsPrivateKey privateKey)
    {
        // Extrae los parámetros del algoritmo, I el identificador del árbol, Q índice de la hoja en el árbol de Merkle y MasterSecret seed.
        return lms_ots_generateChain(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), privateKey.getMasterSecret());
    }

    static byte[][][] lms_ots_generateChain(LMOtsParameters parameter, byte[] I, int q, byte[] masterSecret)
    {
        // Contexto del hash para calcular la cadena de Winternitz
        Digest ctx = DigestUtil.getDigest(parameter);
        // Buffer de trabajo para las iteraciones, I || q || i || j || hash_previo
        byte[] buf = Composer.compose()
                .bytes(I)
                .u32str(q)
                .padUntil(0, 23 + ctx.getDigestSize())
                .build();

        // Derivador de semillas determinista
        SeedDerive derive = new SeedDerive(I, masterSecret, DigestUtil.getDigest(parameter));
        derive.setQ(q);
        derive.setJ(0);

        int p = parameter.getP(); // numero de cadenas de Winternitz
        int n = parameter.getN(); // tamaño del hash en bytes
        final int twoToWminus1 = (1 << parameter.getW()) - 1; // iteraciones por cadena (2^w - 1)

        byte[][][] sk = new byte[p][twoToWminus1+1][n]; // matriz tridimensional para las cadenas de Winternitz

        for (int i = 0; i < p; i++) // Itera sobre cada una de las p cadenas
        {
            derive.deriveSeed(buf, i < p - 1, ITER_PREV); // Deriva la semilla privada para la cadena i y escribe en la posición 23 del buffer su valor
            Pack.shortToBigEndian((short)i, buf, ITER_K); // Escribe el índice i en la posición 20 del buffer. Esto vincula cada hash al índice de la cadena, evitando que dos cadenas produzcan el mismo valor.

            System.arraycopy(buf, ITER_PREV, sk[i][0], 0, n); // j=0: guardamos la semilla privada antes de cualquier iteración

            for (int j = 0; j < twoToWminus1; j++) // Itera sobre cada uno de los (2^w - 1) nodos de la cadena de la posición i
            {
                // En cada iteración, el hash del valor anterior en la cadena se vuelve la entrada del siguiente, junto con
                // los valores de I, q, i, j

                buf[ITER_J] = (byte)j; // Escribe el índice j en la posición 22 del buffer.
                ctx.update(buf, 0, buf.length); // Hashea el buffer
                ctx.doFinal(buf, ITER_PREV); // Sobreescribe la parte del hash previo con el resultado anterior (posición 23 del buffer)

                // Guarda el estado del hash tras la iteración j de la cadena i en sk
                System.arraycopy(buf, ITER_PREV, sk[i][j+1], 0, n);
            }
        }

        return sk;
    }

    public static LMOtsPublicKey lms_ots_publicKeyFromChain(LMOtsPrivateKey privateKey, byte[][][] sk)
    {
        byte[] K = lms_ots_publicKeyFromChain(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), sk);
        return new LMOtsPublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), K);
    }

    static byte[] lms_ots_publicKeyFromChain(LMOtsParameters parameter, byte[] I, int q, byte[][][] sk)
    {
        // Contexto del hash para calcular el valor final de la clave pública
        Digest publicContext = DigestUtil.getDigest(parameter);
        // Prefijo del hash de la clave pública, I || q || 0x8080 || 0x0000
        byte[] prehashPrefix = Composer.compose()
                .bytes(I)
                .u32str(q)
                .u16str(D_PBLC) // Garantiza que este hash no pueda confundirse con otros del protocolo
                .padUntil(0, 22)
                .build();
        // Introduce el prefijo al contexto del hash de la clave pública
        publicContext.update(prehashPrefix, 0, prehashPrefix.length);

        int p = parameter.getP(); // numero de cadenas de Winternitz
        int n = parameter.getN(); // tamaño del hash en bytes
        final int twoToWminus1 = (1 << parameter.getW()) - 1; // iteraciones por cadena (2^w - 1)

        for (int i = 0; i < p; i++)
        {
            // El extremo público de cada cadena es el último valor, en j = twoToWminus1 - 1
            publicContext.update(sk[i][twoToWminus1], 0, n);
        }

        byte[] K = new byte[publicContext.getDigestSize()];
        publicContext.doFinal(K, 0);

        return K;
    }

}
