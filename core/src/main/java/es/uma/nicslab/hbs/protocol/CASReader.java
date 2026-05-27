package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.model.CRV;

import java.io.IOException;

/**
 * Abstracción de lectura del Content Addressable Storage.
 *
 * Usada por el Aggregator para descargar el CRV de un KeyID concreto
 * y la Coalition List durante el proceso de firma.
 *
 * El CID de cada CRV se obtiene previamente de la CoalitionEntry
 * correspondiente al KeyID que se quiere firmar.
 */
public interface CASReader {

    /**
     * Recupera el CRV identificado por su CID.
     *
     * @param crvCid CID del CRV (SHA-256 hex, 64 chars).
     * @return CRV deserializado.
     */
    CRV getCRV(String crvCid) throws IOException;

    /**
     * Recupera la Coalition List identificada por su CID.
     *
     * @param clCid CID de la CL (SHA-256 hex, 64 chars).
     * @return Array de CoalitionEntry, uno por KeyID.
     */
    CoalitionEntry[] getCL(String clCid) throws IOException;

}