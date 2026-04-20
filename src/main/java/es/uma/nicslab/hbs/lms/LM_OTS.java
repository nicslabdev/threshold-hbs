package es.uma.nicslab.hbs.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class LM_OTS
{

    // Constante de dominio para la generación de clave pública (domain separation)
    private static final short D_PBLC = (short)0x8080;

    // Índices que indican en qué posición del buffer se escriben ciertos campos
    private static final int ITER_K = 20; // Indice i
    private static final int ITER_PREV = 23; // Resultado del hash previo
    private static final int ITER_J = 22; // Contador j

    // Índice especial utilizado por SeedDerive
    static final int SEED_RANDOMISER_INDEX = ~2;

    // Tamaño máximo del hash soportado
    static final int MAX_HASH = 32;

    // Constante de dominio para la firma (domain separation)
    static final short D_MESG = (short)0x8181;


    public static int coef(byte[] S, int i, int w)
    {
        int index = (i * w) / 8;
        int digits_per_byte = 8 / w;
        int shift = w * (~i & (digits_per_byte - 1));
        int mask = (1 << w) - 1;

        return (S[index] >>> shift) & mask;
    }


    public static int cksm(byte[] S, int sLen, LMOtsParameters parameters)
    {
        int sum = 0;

        int w = parameters.getW();

        // NB assumption about size of "w" not overflowing integer.
        int twoWpow = (1 << w) - 1;

        for (int i = 0; i < (sLen * 8 / parameters.getW()); i++)
        {
            sum = sum + twoWpow - coef(S, i, parameters.getW());
        }
        return sum << parameters.getLs();
    }


    public static LMOtsPublicKey lms_ots_generatePublicKey(LMOtsPrivateKey privateKey)
    {
        // Extrae los parámetros del algoritmo, I el identificador del árbol, Q índice de la hoja en el árbol de Merkle y MasterSecret seed.
        byte[] K = lms_ots_generatePublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), privateKey.getMasterSecret());
        return new LMOtsPublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), K);
    }

    static byte[] lms_ots_generatePublicKey(LMOtsParameters parameter, byte[] I, int q, byte[] masterSecret)
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


        for (int i = 0; i < p; i++) // Itera sobre cada una de las p cadenas
        {
            derive.deriveSeed(buf, i < p - 1, ITER_PREV); // Deriva la semilla privada para la cadena i y escribe en la posición 23 del buffer su valor
            Pack.shortToBigEndian((short)i, buf, ITER_K); // Escribe el índice i en la posición 20 del buffer. Esto vincula cada hash al índice de la cadena, evitando que dos cadenas produzcan el mismo valor.
            for (int j = 0; j < twoToWminus1; j++) // Itera sobre cada uno de los (2^w - 1) nodos de la cadena de la posición i
            {
                // En cada iteración, el hash del valor anterior en la cadena se vuelve la entrada del siguiente, junto con
                // los valores de I, q, i, j

                buf[ITER_J] = (byte)j; // Escribe el índice j en la posición 22 del buffer.
                ctx.update(buf, 0, buf.length); // Hashea el buffer
                ctx.doFinal(buf, ITER_PREV); // Sobreescribe la parte del hash previo con el resultado anterior (posición 23 del buffer)
            }
            publicContext.update(buf, ITER_PREV, n); // Acumula el extremo de la cadena i en el hash global de la clave pública
        }

        byte[] K = new byte[publicContext.getDigestSize()];
        publicContext.doFinal(K, 0); // Finaliza el hash global de la clave pública. Compromiso con todas las claves privadas de las p cadenas

        return K;

    }

    public static LMOtsSignature lm_ots_generate_signature(LMSigParameters sigParams, LMOtsPrivateKey privateKey, byte[][] path, byte[] message, boolean preHashed)
    {
        //
        // Add the randomizer.
        //

        byte[] C;
        byte[] Q = new byte[MAX_HASH + 2];

        if (!preHashed)
        {
            LMSContext qCtx = privateKey.getSignatureContext(sigParams, path);

            LmsUtils.byteArray(message, 0, message.length, qCtx);

            C = qCtx.getC();
            Q = qCtx.getQ();
        }
        else
        {
            int n = privateKey.getParameter().getN();
            
            C = new byte[n];
            System.arraycopy(message, 0, Q, 0, n);
        }

        return lm_ots_generate_signature(privateKey, Q, C);
    }

    public static LMOtsSignature lm_ots_generate_signature(LMOtsPrivateKey privateKey, byte[] Q, byte[] C)
    {
        LMOtsParameters parameter = privateKey.getParameter();

        int n = parameter.getN();
        int p = parameter.getP();
        int w = parameter.getW();

        byte[] sigComposer = new byte[p * n];

        Digest ctx = DigestUtil.getDigest(parameter);

        SeedDerive derive = privateKey.getDerivationFunction();

        int cs = cksm(Q, n, parameter);
        Q[n] = (byte)((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte)cs;

        byte[] tmp = Composer.compose().bytes(privateKey.getI()).u32str(privateKey.getQ()).padUntil(0, ITER_PREV + n).build();

        derive.setJ(0);
        for (int i = 0; i < p; i++)
        {
            Pack.shortToBigEndian((short)i, tmp, ITER_K);
            derive.deriveSeed(tmp, i < p - 1, ITER_PREV);
            int a = coef(Q, i, w);
            for (int j = 0; j < a; j++)
            {
                tmp[ITER_J] = (byte)j;
                ctx.update(tmp, 0, ITER_PREV + n);
                ctx.doFinal(tmp, ITER_PREV);
            }
            System.arraycopy(tmp, ITER_PREV, sigComposer, n * i, n);
        }

        return new LMOtsSignature(parameter, C, sigComposer);
    }

    public static boolean lm_ots_validate_signature(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message, boolean prehashed)
        throws LMSException
    {
        if (!signature.getType().equals(publicKey.getParameter()))
        {
            throw new LMSException("public key and signature ots types do not match");
        }
        return Arrays.areEqual(lm_ots_validate_signature_calculate(publicKey, signature, message), publicKey.getK());
    }

    public static byte[] lm_ots_validate_signature_calculate(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message)
    {
        LMSContext ctx = publicKey.createOtsContext(signature);

        LmsUtils.byteArray(message, ctx);

        return lm_ots_validate_signature_calculate(ctx);
    }

    public static byte[] lm_ots_validate_signature_calculate(LMSContext context)
    {
        LMOtsPublicKey publicKey = context.getPublicKey();
        LMOtsParameters parameter = publicKey.getParameter();
        Object sig = context.getSignature();
        LMOtsSignature signature;
        if (sig instanceof LMSSignature)
        {
            signature = ((LMSSignature)sig).getOtsSignature();
        }
        else
        {
            signature = (LMOtsSignature)sig;
        }

        int n = parameter.getN();
        int w = parameter.getW();
        int p = parameter.getP();
        byte[] Q = context.getQ();

        int cs = cksm(Q, n, parameter);
        Q[n] = (byte)((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte)cs;

        byte[] I = publicKey.getI();
        int    q = publicKey.getQ();

        Digest finalContext = DigestUtil.getDigest(parameter);
        LmsUtils.byteArray(I, finalContext);
        LmsUtils.u32str(q, finalContext);
        LmsUtils.u16str(D_PBLC, finalContext);

        byte[] tmp = Composer.compose()
            .bytes(I)
            .u32str(q)
            .padUntil(0, ITER_PREV + n).build();

        int max_digit = (1 << w) - 1;

        byte[] y = signature.getY();

        Digest ctx = DigestUtil.getDigest(parameter);
        for (int i = 0; i < p; i++)
        {
            Pack.shortToBigEndian((short)i, tmp, ITER_K);
            System.arraycopy(y, i * n, tmp, ITER_PREV, n);
            int a = coef(Q, i, w);

            for (int j = a; j < max_digit; j++)
            {
                tmp[ITER_J] = (byte)j;
                ctx.update(tmp, 0, ITER_PREV + n);
                ctx.doFinal(tmp, ITER_PREV);
            }

            finalContext.update(tmp, ITER_PREV, n);
        }

        byte[] K = new byte[n];
        finalContext.doFinal(K, 0);

        return K;
    }
}
