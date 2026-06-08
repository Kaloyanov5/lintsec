package com.lintsec.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanCancellationRegistryTest {

    @Test
    void requestThenIsRequestedThenClear() {
        ScanCancellationRegistry registry = new ScanCancellationRegistry();

        assertFalse(registry.isRequested(42L), "unknown id should not be requested");

        registry.request(42L);
        assertTrue(registry.isRequested(42L));

        registry.clear(42L);
        assertFalse(registry.isRequested(42L), "cleared id should not be requested");
    }

    @Test
    void clearIsIdempotentAndIdsAreIndependent() {
        ScanCancellationRegistry registry = new ScanCancellationRegistry();

        registry.request(1L);
        registry.clear(2L);   // clearing an absent id must not throw
        registry.clear(2L);

        assertTrue(registry.isRequested(1L));
        assertFalse(registry.isRequested(2L));
    }
}
