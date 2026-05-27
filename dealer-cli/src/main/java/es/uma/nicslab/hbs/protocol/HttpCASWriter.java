package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.model.CRV;

import java.io.IOException;

/**
 * Implementación HTTP de CASWriter para el Dealer.
 *
 * Serializa y sube CRVs y la Coalition List al CAS HTTP durante el Setup.
 * Devuelve el CID de cada blob subido para que el Dealer pueda construir
 * la CoalitionEntry[] y publicar la CL final.
 */
public class HttpCASWriter implements CASWriter {

    private final CASClient cas;

    public HttpCASWriter(CASClient cas) {
        this.cas = cas;
    }

    @Override
    public String putCRV(int keyID, CRV crv) throws IOException {
        byte[] blob = CRVSerializer.serialize(crv);
        return cas.put(blob);
    }

    @Override
    public String putCL(CoalitionEntry[] cl) throws IOException {
        byte[] blob = CLSerializer.serialize(cl);
        return cas.put(blob);
    }
}