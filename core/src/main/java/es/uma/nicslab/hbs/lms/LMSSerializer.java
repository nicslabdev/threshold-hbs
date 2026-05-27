package es.uma.nicslab.hbs.lms;

import es.uma.nicslab.hbs.model.ThresholdSignature;

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
        LMOtsSignature otsSig = new LMOtsSignature(otsParameters, sig.getR(), sig.getZ());
        LMSSignature lmsSig = new LMSSignature(keyId, otsSig, lmsParameters, sig.getPATH());
        return lmsSig.getEncoded();
    }

    /**
     * Método estático de conveniencia.
     * Extrae los parámetros OTS y LMS directamente de la clave pública LMS.
     *
     * @param sig          Firma threshold a serializar.
     * @param keyId        Índice OTS (q) — identifica la hoja del árbol.
     * @param lmsPublicKey Clave pública LMS con los parámetros del esquema.
     */
    public static byte[] serialize(ThresholdSignature sig, int keyId, LMSPublicKeyParameters lmsPublicKey) throws IOException {
        LMOtsParameters otsParams = lmsPublicKey.getOtsParameters();
        LMSigParameters lmsParams = lmsPublicKey.getSigParameters();
        return new LMSSerializer(otsParams, lmsParams).serialize(sig, keyId);
    }
}