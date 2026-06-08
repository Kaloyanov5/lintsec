package com.lintsec.scanner;

import com.lintsec.crawler.CancellationToken;
import com.lintsec.crawler.CrawlResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScannerCancellationTest {

    private static CrawlResult emptyCrawl() {
        return new CrawlResult(Set.of("https://example.com"), List.of(), Set.of());
    }

    /** Records whether it was invoked so we can assert the loop short-circuited. */
    private static final class RecordingModule implements ScannerModule {
        final AtomicInteger calls = new AtomicInteger();
        public String name() { return "recording"; }
        public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
            calls.incrementAndGet();
            return List.of();
        }
    }

    @Test
    void preCancelledTokenRunsNoModules() {
        RecordingModule module = new RecordingModule();
        Scanner scanner = new Scanner(List.of(module));

        List<ScanFinding> findings = scanner.scan(emptyCrawl(), null, () -> true);

        assertTrue(findings.isEmpty());
        assertEquals(0, module.calls.get(), "cancelled scan must not invoke modules");
    }

    @Test
    void liveTokenRunsModules() {
        RecordingModule module = new RecordingModule();
        Scanner scanner = new Scanner(List.of(module));

        scanner.scan(emptyCrawl(), null, CancellationToken.NONE);

        assertEquals(1, module.calls.get());
    }
}
