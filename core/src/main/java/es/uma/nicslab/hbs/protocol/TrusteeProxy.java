package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.model.Round1Msg;
import es.uma.nicslab.hbs.model.Round2Msg;

/**
 * Abstracción de un Trustee desde el punto de vista del Aggregator.
 *
 * Permite que el Aggregator sea agnóstico sobre si el trustee es local
 * (en memoria, para tests) o remoto (via gRPC, en producción).
 *
 * Implementaciones:
 *  - LocalTrusteeProxy → envuelve un Trustee local (core)
 *  - GrpcTrusteeProxy → llama al trustee via gRPC (aggregator-server)
 */
public interface TrusteeProxy {

    /**
     * Ejecuta el Round 1 del protocolo de firma.
     *
     * @param keyID   KeyID a firmar (bytes).
     * @param message Mensaje a firmar.
     * @return Round1Msg con R_t y CHK_t, o null si el trustee devuelve ⊥.
     */
    Round1Msg shardSign1(byte[] keyID, byte[] message) throws Exception;

    /**
     * Ejecuta la Round 2 del protocolo de firma.
     *
     * @param keyID KeyID en curso (bytes).
     * @param R     Randomizer reconstruido.
     * @param chkI  CHK[i] correspondiente a este trustee.
     * @return Round2Msg con PATH_t y Z_t, o null si el trustee devuelve ⊥.
     */
    Round2Msg shardSign2(byte[] keyID, byte[] R, byte[] chkI) throws Exception;
}