package es.uma.nicslab.hbs.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Pack;

public class LM_OTS_WITH_CHAIN {

    // Constante de dominio para la generación de clave pública (domain separation)
    private static final short D_PBLC = (short)0x8080;

    // Índices que indican en qué posición del buffer se escriben ciertos campos
    private static final int ITER_K = 20; // Indice i
    private static final int ITER_PREV = 23; // Resultado del hash previo
    private static final int ITER_J = 22; // Contador j

    // Tamaño máximo del hash soportado
    static final int MAX_HASH = 32;


    // Extrae el coeficiente i-ésimo de una cadena de bytes, donde cada coeficiente tiene w bits de ancho
    public static int coef(byte[] S, int i, int w) {
        int index = (i * w) / 8;
        int digits_per_byte = 8 / w;
        // Calcula cuántos bits hay que desplazar a la derecha para alinear el coeficiente i con el bit menos significativo
        int shift = w * (~i & (digits_per_byte - 1));
        int mask = (1 << w) - 1;

        return (S[index] >>> shift) & mask;
    }


    // Calcula el checksum definido en RFC 8554
    public static int cksm(byte[] S, int sLen, LMOtsParameters parameters) {
        int sum = 0;

        int w = parameters.getW();

        // NB assumption about size of "w" not overflowing integer.
        int twoWpow = (1 << w) - 1;

        for (int i = 0; i < (sLen * 8 / parameters.getW()); i++) // Itera sobre todos los coeficientes del mensaje S
        {
            sum = sum + twoWpow - coef(S, i, parameters.getW()); // Suma el complemento del coeficiente respecto al máximo
        }
        return sum << parameters.getLs();
    }


    public static LMOtsChain lms_ots_generateChain(LMOtsPrivateKey privateKey) {
        LMOtsParameters parameter = privateKey.getParameter();
        byte[] I = privateKey.getI(); // Identificador del árbol
        int q = privateKey.getQ(); // Índice de la hoja en el árbol
        return new LMOtsChain(parameter, lms_ots_generateChain(parameter, I, q, privateKey.getMasterSecret()), I, q);
    }

    static byte[][][] lms_ots_generateChain(LMOtsParameters parameter, byte[] I, int q, byte[] masterSecret) {
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

        byte[][][] SK = new byte[p][twoToWminus1+1][n]; // matriz tridimensional para las cadenas de Winternitz

        for (int i = 0; i < p; i++) // Itera sobre cada una de las p cadenas
        {
            // Deriva la semilla privada para la cadena i y escribe en la posición 23 del buffer su valor
            derive.deriveSeed(buf, i < p - 1, ITER_PREV);
            // Escribe el índice i en la posición 20 del buffer. Esto vincula cada hash al índice de la cadena, evitando que dos cadenas produzcan el mismo valor.
            Pack.shortToBigEndian((short)i, buf, ITER_K);

            System.arraycopy(buf, ITER_PREV, SK[i][0], 0, n); // j=0: guardamos la semilla privada antes de cualquier iteración

            for (int j = 0; j < twoToWminus1; j++) // Itera sobre cada uno de los (2^w - 1) nodos de la cadena de la posición i
            {
                // En cada iteración, el hash del valor anterior en la cadena se vuelve la entrada del siguiente, junto con
                // los valores de I, q, i, j

                buf[ITER_J] = (byte)j; // Escribe el índice j en la posición 22 del buffer.
                ctx.update(buf, 0, buf.length); // Hashea el buffer
                ctx.doFinal(buf, ITER_PREV); // Sobreescribe la parte del hash previo con el resultado anterior (posición 23 del buffer)

                // Guarda el estado del hash tras la iteración j de la cadena i en SK
                System.arraycopy(buf, ITER_PREV, SK[i][j+1], 0, n);
            }
        }

        return SK;
    }


    public static LMOtsPublicKey lms_ots_publicKeyFromChain(LMOtsChain chain) {

        LMOtsParameters parameter = chain.getParameter();
        byte[] I = chain.getI();
        int q = chain.getQ();
        byte[][][] SK = chain.getSK();

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
            publicContext.update(SK[i][twoToWminus1], 0, n);
        }

        byte[] K = new byte[publicContext.getDigestSize()];
        publicContext.doFinal(K, 0);

        return new LMOtsPublicKey(parameter, I, q, K);
    }

    public static LMOtsSignature lm_ots_generate_signatureFromChain(LMOtsChain lmOtsChain, byte[] message, byte[] C) {
        LMOtsParameters parameter = lmOtsChain.getParameter();
        byte[][][] SK = lmOtsChain.getSK();
        
        int n = parameter.getN();
        int p = parameter.getP();
        int w = parameter.getW();

        byte[] Q = new byte[MAX_HASH + 2];

        System.arraycopy(message, 0, Q, 0, n);

        // Calcular checksum y añadirlo a Q
        int cs = cksm(Q, n, parameter);
        Q[n]     = (byte)((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte) cs;

        byte[] sigComposer = new byte[p * n];

        for (int i = 0; i < p; i++)
        {
            // Coeficiente: cuántos pasos se dieron en la firma original
            int a = coef(Q, i, w);

            // En SK[i][a] está el resultado de hashear SK[i][0] a veces
            System.arraycopy(SK[i][a], 0, sigComposer, n * i, n);
        }

        return new LMOtsSignature(parameter, C, sigComposer);
    }

    public static byte[] lm_ots_generate_ZFromSK(byte[] h, byte[][][] SK, LMOtsParameters parameter) {

        int n = parameter.getN();
        int p = parameter.getP();
        int w = parameter.getW();

        byte[] Q = new byte[MAX_HASH + 2];
        System.arraycopy(h, 0, Q, 0, n);

        // Checksum
        int cs = cksm(Q, n, parameter);
        Q[n] = (byte)((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte) cs;

        byte[] Z = new byte[p * n];

        for (int i = 0; i < p; i++) {
            int a = coef(Q, i, w);
            // SK[i][a] es el valor en el paso a de la cadena i del trustee t
            System.arraycopy(SK[i][a], 0, Z, n * i, n);
        }

        return Z;
    }

}
