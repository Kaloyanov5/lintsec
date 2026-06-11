package com.lintsec.sse;

import com.lintsec.dto.ScanEvent;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the late-subscriber replay: the registry caches the most recent non-terminal event per
 * scan and replays it to an emitter that subscribes mid-scan, then clears it on a terminal event.
 */
class SseEmitterRegistryTest {

    /** Captures everything sent through it so the test can assert on replayed events. */
    private static final class CapturingEmitter extends SseEmitter {
        final List<Object> sent = new ArrayList<>();

        @Override
        public void send(SseEmitter.SseEventBuilder builder) throws IOException {
            // Record the data payload of each event set built via SseEmitter.event().data(...).
            for (var entry : builder.build()) {
                if (entry.getData() instanceof ScanEvent event) sent.add(event);
            }
        }
    }

    private static ScanEvent event(ScanEvent.EventType type, int pages) {
        return new ScanEvent(1L, type, pages, 0, null);
    }

    @Test
    void replaysLatestNonTerminalEventToLateSubscriber() {
        SseEmitterRegistry registry = new SseEmitterRegistry();
        registry.onScanEvent(event(ScanEvent.EventType.STARTED, 0));
        registry.onScanEvent(event(ScanEvent.EventType.CRAWL_COMPLETE, 7));

        CapturingEmitter late = new CapturingEmitter();
        registry.replayLatest(1L, late);

        assertEquals(1, late.sent.size());
        ScanEvent replayed = (ScanEvent) late.sent.get(0);
        assertEquals(ScanEvent.EventType.CRAWL_COMPLETE, replayed.type());
        assertEquals(7, replayed.pagesCrawled());
    }

    @Test
    void replayIsNoopWhenNoEventPublishedYet() {
        SseEmitterRegistry registry = new SseEmitterRegistry();
        CapturingEmitter late = new CapturingEmitter();
        registry.replayLatest(1L, late);
        assertTrue(late.sent.isEmpty());
    }

    @Test
    void terminalEventClearsTheCacheSoNothingIsReplayed() {
        SseEmitterRegistry registry = new SseEmitterRegistry();
        registry.onScanEvent(event(ScanEvent.EventType.CRAWL_COMPLETE, 7));
        registry.onScanEvent(event(ScanEvent.EventType.SCAN_COMPLETE, 7));

        CapturingEmitter late = new CapturingEmitter();
        registry.replayLatest(1L, late);
        assertTrue(late.sent.isEmpty());
    }
}
