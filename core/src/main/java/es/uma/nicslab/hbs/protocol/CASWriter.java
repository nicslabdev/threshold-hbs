package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.model.CRV;

import java.io.IOException;

/**
 * Abstracción de escritura del Content Addressable Storage.
 *
 * Usada por el Dealer durante el Setup para publicar el CRV de cada
 * KeyID y la Coalition List completa en el CAS.
 *
 * Cada operación devuelve el CID asignado al dato almacenado.
 * El Dealer recopila estos CIDs para construir la CoalitionEntry[]
 * y publicar la CL final.
 */
public interface CASWriter {

    /**
     * Almacena el CRV de un KeyID concreto.
     *
     * @param keyID Identificador del KeyID (0..D-1).
     * @param crv   CRV a almacenar.
     * @return CID asignado al CRV almacenado (SHA-256 hex, 64 chars).
     */
    String putCRV(int keyID, CRV crv) throws IOException;

    /**
     * Almacena la Coalition List completa.
     *
     * @param cl Array de CoalitionEntry, uno por KeyID.
     * @return CID asignado a la CL almacenada (SHA-256 hex, 64 chars).
     */
    String putCL(CoalitionEntry[] cl) throws IOException;
}