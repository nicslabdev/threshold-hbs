package es.uma.nicslab.hbs.model;

public class SetupResult {

    private final CRV crv;
    private final TrusteeShare[] shares;

    public SetupResult(CRV crv, TrusteeShare[] shares) {
        this.crv = crv;
        this.shares = shares != null ? shares.clone() : null;
    }

    public CRV getCRV() {
        return crv;
    }

    public TrusteeShare[] getShares() {
        return shares != null ? shares.clone() : null;
    }

}
