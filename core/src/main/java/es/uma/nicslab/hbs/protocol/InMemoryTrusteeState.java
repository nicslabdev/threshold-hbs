package es.uma.nicslab.hbs.protocol;

import java.util.HashSet;
import java.util.Set;

/**
 * Implementación en memoria de TrusteeStateStore.
 *
 * Replica el comportamiento actual de los campos keyList y current/keyID
 * de Trustee.java. Usada en los tests unitarios de core donde no se
 * necesita SQLite ni disco.
 */
public class InMemoryTrusteeState implements TrusteeState {

    private final Set<Integer> keyList = new HashSet<>();
    private SigningState signingState = null;

    @Override
    public void initKeyList(int[] keyIDs) {
        keyList.clear();
        for (int keyID : keyIDs) {
            keyList.add(keyID);
        }
    }

    @Override
    public synchronized boolean claimKeyID(int keyID) {
        return keyList.remove(keyID);
    }

    @Override
    public synchronized void saveSigningState(int keyID, byte[] message) {
        this.signingState = new SigningState(keyID, message.clone());
    }

    @Override
    public synchronized SigningState loadAndClearSigningState(int keyID) {
        SigningState state = this.signingState;
        if (state.keyID()!=keyID) {
            return null;
        }
        this.signingState = null;
        return state;
    }

    @Override
    public synchronized boolean hasSigningState(int keyID) {
        return signingState != null;
    }
}