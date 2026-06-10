package com.lintsec.sse;

import com.lintsec.dto.ScanEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class SseEmitterRegistry {
    private static final long SCAN_SSE_TIMEOUT_MS = 600_000L;
    private static final Logger log = LoggerFactory.getLogger(SseEmitterRegistry.class);

    private final Map<Long, List<SseEmitter>> emittersByScanId = new ConcurrentHashMap<>();

    public SseEmitter register(Long scanId) {
        SseEmitter emitter = new SseEmitter(SCAN_SSE_TIMEOUT_MS);
        emittersByScanId.computeIfAbsent(scanId, k -> new CopyOnWriteArrayList<>()).add(emitter);

        Runnable remove = () -> removeEmitter(scanId, emitter);
        emitter.onCompletion(remove);
        // Complete the emitter on timeout: without this, the timeout dispatch raises an
        // AsyncRequestTimeoutException (logged as a noisy stack trace). complete() pre-empts it,
        // and onCompletion then removes the emitter from the registry.
        emitter.onTimeout(emitter::complete);
        emitter.onError(t -> remove.run());

        return emitter;
    }

    /**
     * Sends a single terminal event to any emitters currently registered for an already-finished
     * scan, then completes them. The live stream has no replay, so a client that subscribes after
     * the scan ended (or reconnects post-completion) would otherwise hold the connection open until
     * the timeout. Removing the bucket first also closes the register/terminal-event race window.
     */
    public void emitTerminalSnapshot(Long scanId, ScanEvent.EventType type, int pagesCrawled, int findingsCount) {
        List<SseEmitter> emitters = emittersByScanId.remove(scanId);
        if (emitters == null || emitters.isEmpty()) return;

        ScanEvent event = new ScanEvent(scanId, type, pagesCrawled, findingsCount, null);
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name("scan").data(event));
                emitter.complete();
            } catch (Exception e) {
                emitter.completeWithError(e);
            }
        }
    }

    @EventListener
    public void onScanEvent(ScanEvent event) {
        List<SseEmitter> emitters = emittersByScanId.get(event.scanId());
        if (emitters == null || emitters.isEmpty()) return;

        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name("scan").data(event));
            } catch (Exception e) {
                log.warn("failed to send SSE event for scan {}: {}", event.scanId(), e.getMessage());
                emitter.completeWithError(e);
            }
        }

        // On terminal events, drop the bucket so it gets garbage-collected
        if (isTerminal(event.type())) {
            emittersByScanId.remove(event.scanId());
            for (SseEmitter emitter : emitters) emitter.complete();
        }
    }

    private void removeEmitter(Long scanId, SseEmitter emitter) {
        emittersByScanId.computeIfPresent(scanId, (k, list) -> {
            list.remove(emitter);
            return list.isEmpty() ? null : list;
        });
    }

    private static boolean isTerminal(ScanEvent.EventType type) {
        return type == ScanEvent.EventType.SCAN_COMPLETE
                || type == ScanEvent.EventType.FAILED
                || type == ScanEvent.EventType.CANCELLED;
    }
}
