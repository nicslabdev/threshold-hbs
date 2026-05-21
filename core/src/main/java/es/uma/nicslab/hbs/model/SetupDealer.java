package es.uma.nicslab.hbs.model;

import es.uma.nicslab.hbs.protocol.PublicBulletinBoard;
import es.uma.nicslab.hbs.roles.Trustee;

public class SetupDealer {

    private final Trustee[] trustees;
    private final PublicBulletinBoard board;

    public SetupDealer(Trustee[] trustees, PublicBulletinBoard board) {
        this.board = board;
        this.trustees = trustees;
    }

    public PublicBulletinBoard getBoard() {
        return board;
    }

    public Trustee[] getTrustees() {
        return trustees;
    }

}
