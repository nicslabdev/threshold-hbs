package es.uma.nicslab.hbs.protocol;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * In-memory implementation of TrusteeState.
 *
 * Used by core tests and local in-process executions where SQLite persistence
 * is not required.
 *
 * Its semantics mirror SQLiteTrusteeState:
 *
 *  - KeyIDs are claimed atomically and can never be reused.
 *  - Signing state is maintained independently per KeyID.
 *  - Multiple signing operations for different KeyIDs may therefore be
 *    active concurrently.
 *  - Round 2 atomically retrieves and removes the state associated with
 *    the requested KeyID.
 */
public class InMemoryTrusteeState implements TrusteeState {

    private final Set<Integer> keyList = new HashSet<>();
    private final Map<Integer, SigningState> signingStates = new HashMap<>();

    @Override
    public synchronized void initKeyList(int[] keyIDs) {
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
        signingStates.put(
                keyID,
                new SigningState(keyID, message.clone())
        );
    }

    @Override
    public synchronized SigningState loadAndClearSigningState(int keyID) {
        return signingStates.remove(keyID);
    }

    @Override
    public synchronized boolean hasSigningState(int keyID) {
        return signingStates.containsKey(keyID);
    }
}
