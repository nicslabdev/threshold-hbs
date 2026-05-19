package es.uma.nicslab.hbs.lms;

import es.uma.nicslab.hbs.model.ThresholdSignature;
import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;

import java.io.IOException;

public class LMSSerializer {

    private final LMOtsParameters otsParameters;
    private final LMSigParameters lmsParameters;

    public LMSSerializer(LMOtsParameters otsParameters, LMSigParameters lmsParameters) {
        this.otsParameters = otsParameters;
        this.lmsParameters = lmsParameters;
    }

    /**
     * Serializa una ThresholdSignature al formato binario RFC 8554,
     * idéntico al que produce LMSSignature.getEncoded() de Bouncy Castle.
     *
     * Formato:
     *   u32str(q)        — KeyID
     *   u32str(ots_type) — tipo OTS
     *   C = R            — randomizer (n bytes)
     *   y = Z            — firma Winternitz (p*n bytes)
     *   u32str(lms_type) — tipo LMS
     *   path[0..h-1]     — nodos Merkle (h*n bytes cada uno)
     */
    public byte[] serialize(ThresholdSignature sig, int keyId) throws IOException {

        // Construir LMOtsSignature con R como C y Z como y
        LMOtsSignature otsSig = new LMOtsSignature(otsParameters, sig.getR(), sig.getZ());

        // Construir LMSSignature con q, otsSig, lmsParameters y PATH
        LMSSignature lmsSig = new LMSSignature(keyId, otsSig, lmsParameters, sig.getPATH());

        return lmsSig.getEncoded();
    }

    /**
     * Método estático de conveniencia para el ProtocolRunner.
     * Extrae los parámetros OTS y LMS directamente del PublicBulletinBoard.
     *
     * @param sig    firma threshold a serializar
     * @param board  tablón público con los parámetros del árbol LMS
     * @param keyId  índice OTS (q) — identifica la hoja del árbol
     */
    public static byte[] serialize(ThresholdSignature sig,
                                   PublicBulletinBoard board,
                                   int keyId) throws IOException {
        LMOtsParameters otsParams = board.getParameter();
        LMSigParameters lmsParams = board.getPublicKey().getSigParameters();
        LMSSerializer serializer  = new LMSSerializer(otsParams, lmsParams);
        return serializer.serialize(sig, keyId);
    }

}