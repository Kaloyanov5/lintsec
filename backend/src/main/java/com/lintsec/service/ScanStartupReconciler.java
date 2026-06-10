package com.lintsec.service;

import com.lintsec.domain.ScanStatus;
import com.lintsec.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * On startup, fails any scan still marked PENDING/RUNNING. The app has no DevTools, so every code
 * change is a full restart; without this, a scan interrupted mid-run stays RUNNING permanently and
 * the user can neither delete it (delete rejects RUNNING) nor meaningfully cancel it (the worker
 * thread no longer exists).
 */
@Component
public class ScanStartupReconciler {

    private static final Logger log = LoggerFactory.getLogger(ScanStartupReconciler.class);

    private final ScanRepository scanRepository;

    public ScanStartupReconciler(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void reconcileInterruptedScans() {
        int reconciled = scanRepository.reconcileStatuses(
                List.of(ScanStatus.PENDING, ScanStatus.RUNNING),
                ScanStatus.FAILED,
                Instant.now(),
                "interrupted by a server restart");
        if (reconciled > 0) {
            log.warn("startup: marked {} interrupted scan(s) as FAILED", reconciled);
        }
    }
}
