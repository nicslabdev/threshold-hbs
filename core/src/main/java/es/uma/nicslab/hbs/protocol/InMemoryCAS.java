package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.model.CRV;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Implementación en memoria de CASReader y CASWriter.
 *
 * Usada en tests unitarios de core donde no se necesita red ni disco.
 * El Dealer escribe a través de CASWriter y el Aggregator lee a través
 * de CASReader, ambos sobre la misma instancia compartida.
 *
 * Los CIDs generados son sintéticos (no SHA-256 reales) pero reproducibles
 * por keyID para CRVs, y aleatorios para la CL.
 */
public class InMemoryCAS implements CASReader, CASWriter {

    private final Map<String, CRV>            crvs = new HashMap<>();
    private final Map<String, CoalitionEntry[]> cls = new HashMap<>();

    // -------------------------------------------------------------------------
    // CASWriter
    // -------------------------------------------------------------------------

    @Override
    public String putCRV(int keyID, CRV crv) {
        String cid = "crv-" + keyID;
        crvs.put(cid, crv);
        return cid;
    }

    @Override
    public String putCL(CoalitionEntry[] cl) {
        String cid = "cl-" + UUID.randomUUID();
        cls.put(cid, cl);
        return cid;
    }

    // -------------------------------------------------------------------------
    // CASReader
    // -------------------------------------------------------------------------

    @Override
    public CRV getCRV(String crvCid) {
        CRV crv = crvs.get(crvCid);
        if (crv == null) {
            throw new IllegalArgumentException("CRV no encontrado para CID: " + crvCid);
        }
        return crv;
    }

    @Override
    public CoalitionEntry[] getCL(String clCid) {
        CoalitionEntry[] cl = cls.get(clCid);
        if (cl == null) {
            throw new IllegalArgumentException("CL no encontrada para CID: " + clCid);
        }
        return cl;
    }
}