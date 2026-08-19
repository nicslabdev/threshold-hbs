package es.uma.nicslab.hbs.protocol;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryTrusteeStateTest {

    private InMemoryTrusteeState store;

    @BeforeEach
    void setUp() {
        store = new InMemoryTrusteeState();
    }

    @Test
    void loadAndClearWithoutStateReturnsNull() {
        assertNull(store.loadAndClearSigningState(42));
    }

    @Test
    void supportsIndependentConcurrentSigningStates() {
        store.saveSigningState(10, "first".getBytes());
        store.saveSigningState(20, "second".getBytes());

        assertTrue(store.hasSigningState(10));
        assertTrue(store.hasSigningState(20));

        SigningState first = store.loadAndClearSigningState(10);
        SigningState second = store.loadAndClearSigningState(20);

        assertNotNull(first);
        assertNotNull(second);

        assertEquals(10, first.keyID());
        assertEquals(20, second.keyID());

        assertArrayEquals("first".getBytes(), first.message());
        assertArrayEquals("second".getBytes(), second.message());
    }

    @Test
    void loadingOneStateDoesNotClearAnother() {
        store.saveSigningState(10, "first".getBytes());
        store.saveSigningState(20, "second".getBytes());

        SigningState first = store.loadAndClearSigningState(10);

        assertNotNull(first);
        assertFalse(store.hasSigningState(10));
        assertTrue(store.hasSigningState(20));
    }

    @Test
    void hasSigningStateIsScopedToKeyId() {
        store.saveSigningState(10, "message".getBytes());

        assertTrue(store.hasSigningState(10));
        assertFalse(store.hasSigningState(11));
    }

    @Test
    void claimedKeyIdCannotBeReused() {
        store.initKeyList(new int[]{0, 1});

        assertTrue(store.claimKeyID(0));
        assertFalse(store.claimKeyID(0));

        assertTrue(store.claimKeyID(1));
    }
}
