package com.lintsec.dto;

import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanResponseTest {

    @Test
    void mirrorsCancelRequestedFromEntity() {
        Scan scan = new Scan();
        scan.setTargetUrl("https://example.com");
        scan.setStatus(ScanStatus.RUNNING);
        scan.setCancelRequested(true);

        ScanResponse response = ScanResponse.from(scan);

        assertTrue(response.cancelRequested());
        assertEquals(ScanStatus.RUNNING, response.status());
    }
}
