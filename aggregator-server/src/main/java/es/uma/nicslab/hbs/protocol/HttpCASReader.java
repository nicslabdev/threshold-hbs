package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.cas.CASClient;
import es.uma.nicslab.hbs.model.CRV;

import java.io.IOException;

/**
 * Implementación HTTP de CASReader para el Aggregator.
 *
 * Descarga CRVs y la Coalition List del CAS HTTP.
 * La verificación de integridad es automática: CasClient comprueba
 * que el SHA-256 del blob descargado coincide con el CID solicitado.
 */
public class HttpCASReader implements CASReader {

    private final CASClient cas;

    public HttpCASReader(CASClient cas) {
        this.cas = cas;
    }

    @Override
    public CRV getCRV(String crvCid) throws IOException {
        byte[] blob = cas.get(crvCid);
        return CRVSerializer.deserialize(blob);
    }

    @Override
    public CoalitionEntry[] getCL(String clCid) throws IOException {
        byte[] blob = cas.get(clCid);
        return CLSerializer.deserialize(blob);
    }
}