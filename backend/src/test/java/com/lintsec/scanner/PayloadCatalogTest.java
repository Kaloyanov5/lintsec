package com.lintsec.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PayloadCatalogTest {

    @Test
    void pathTraversalUnixPayloadTargetsEtcPasswd() {
        assertEquals("../../../../../../../../etc/passwd",
                PayloadCatalog.payloadFor(PayloadId.PATH_TRAVERSAL_UNIX, ""));
    }

    @Test
    void pathTraversalWindowsPayloadTargetsWinIni() {
        assertEquals("..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
                PayloadCatalog.payloadFor(PayloadId.PATH_TRAVERSAL_WINDOWS, ""));
    }

    @Test
    void commandInjectionPayloadsAreCanonical() {
        assertEquals(";id", PayloadCatalog.payloadFor(PayloadId.CMDI_UNIX_ID, ""));
        assertEquals("& ver", PayloadCatalog.payloadFor(PayloadId.CMDI_WINDOWS_VER, ""));
    }

    @Test
    void plainCanaryIsAlphanumericWithNonce() {
        assertEquals("lintsecabc123", PayloadCatalog.payloadFor(PayloadId.XSS_CANARY_PLAIN, "abc123"));
    }

    @Test
    void everyPayloadIdHasADescription() {
        for (PayloadId id : PayloadId.values()) {
            assertNotNull(PayloadCatalog.descriptionFor(id), "missing description for " + id);
        }
    }
}
