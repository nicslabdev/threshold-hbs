package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.model.Round1Msg;
import es.uma.nicslab.hbs.model.Round2Msg;
import es.uma.nicslab.hbs.roles.Trustee;

/**
 * Implementación local de TrusteeProxy.
 *
 * Envuelve un objeto Trustee que vive en el mismo proceso.
 * Usada en tests unitarios y de integración de core donde no
 * se necesita red ni gRPC.
 */
public class LocalTrusteeProxy implements TrusteeProxy {

    private final Trustee trustee;

    public LocalTrusteeProxy(Trustee trustee) {
        this.trustee = trustee;
    }

    @Override
    public Round1Msg shardSign1(byte[] keyID, byte[] message) throws Exception {
        return trustee.shardSign1(keyID, message);
    }

    @Override
    public Round2Msg shardSign2(byte[] keyID, byte[] R, byte[] chkI) throws Exception {
        return trustee.shardSign2(keyID, R, chkI);
    }
}