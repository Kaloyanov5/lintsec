package com.lintsec.crawler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SSRF guard tests. All cases use literal IPs or unresolvable hosts so the suite stays
 * hermetic — no DNS lookups against the network.
 */
class TargetGuardTest {

    @Test
    void blocksLoopback() {
        assertFalse(TargetGuard.isAllowed("http://127.0.0.1/"));
        assertFalse(TargetGuard.isAllowed("http://127.0.0.1:8080/admin"));
        assertFalse(TargetGuard.isAllowed("https://localhost/"));
        assertFalse(TargetGuard.isAllowed("http://[::1]/"));
    }

    @Test
    void blocksCloudMetadataAndLinkLocal() {
        assertFalse(TargetGuard.isAllowed("http://169.254.169.254/latest/meta-data/"));
        assertFalse(TargetGuard.isAllowed("http://169.254.0.1/"));
    }

    @Test
    void blocksPrivateRfc1918Ranges() {
        assertFalse(TargetGuard.isAllowed("http://10.0.0.5/"));
        assertFalse(TargetGuard.isAllowed("http://192.168.1.1/"));
        assertFalse(TargetGuard.isAllowed("http://172.16.0.1/"));
    }

    @Test
    void blocksWildcardAndMulticast() {
        assertFalse(TargetGuard.isAllowed("http://0.0.0.0/"));
        assertFalse(TargetGuard.isAllowed("http://224.0.0.1/"));
    }

    @Test
    void blocksNonHttpSchemes() {
        assertFalse(TargetGuard.isAllowed("ftp://8.8.8.8/"));
        assertFalse(TargetGuard.isAllowed("file:///etc/passwd"));
        assertFalse(TargetGuard.isAllowed("gopher://8.8.8.8/"));
    }

    @Test
    void blocksMalformedOrHostlessUrls() {
        assertFalse(TargetGuard.isAllowed("not a url"));
        assertFalse(TargetGuard.isAllowed("http://"));
        assertFalse(TargetGuard.isAllowed(""));
        assertFalse(TargetGuard.isAllowed(null));
    }

    @Test
    void allowsPublicAddresses() {
        // Literal public IPs — no DNS needed, classified directly.
        assertTrue(TargetGuard.isAllowed("http://8.8.8.8/"));
        assertTrue(TargetGuard.isAllowed("https://1.1.1.1/some/path?q=1"));
    }
}
