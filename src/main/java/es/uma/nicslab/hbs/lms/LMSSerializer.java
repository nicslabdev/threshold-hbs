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

        // Construir LMOtsSignature con R como C y Z como y
        LMOtsSignature otsSig = new LMOtsSignature(otsParameters, sig.getR(), sig.getZ());

        // Construir LMSSignature con q, otsSig, lmsParameters y PATH
        LMSSignature lmsSig = new LMSSignature(keyId, otsSig, lmsParameters, sig.getPATH());

        return lmsSig.getEncoded();
    }
}