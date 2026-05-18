package com.lintsec.service;

import com.lintsec.domain.Finding;
import com.lintsec.dto.ScanEvent;
import com.lintsec.repository.FindingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class ScanCompletionAiListener {

    private static final long DELAY_BETWEEN_CALLS_MS = 1000;
    private static final Logger log = LoggerFactory.getLogger(ScanCompletionAiListener.class);
    private final AiExplanationService explanationService;
    private final FindingRepository findingRepository;

    public ScanCompletionAiListener(AiExplanationService explanationService, FindingRepository findingRepository) {
        this.explanationService = explanationService;
        this.findingRepository = findingRepository;
    }

    @EventListener
    @Async
    public void onScanComplete(ScanEvent event) {
        if (event.type() != ScanEvent.EventType.SCAN_COMPLETE) return;
        Long scanId = event.scanId();
        List<Finding> scanFindings = findingRepository.findByScanIdOrderBySeverityAscCreatedAtAsc(scanId);
        log.info("starting AI explanations for scan {} ({} findings)", scanId, scanFindings.size());

        int explained = 0;
        int skipped = 0;
        for (Finding finding : scanFindings) {
            Optional<String> text = explanationService.explain(finding);
            if (text.isPresent()) {
                try {
                    finding.setAiExplanation(text.get());
                    findingRepository.save(finding);
                    explained++;
                } catch (Exception e) {
                    log.warn("failed to save AI explanation for finding {}: {}", finding.getId(), e.getMessage());
                    skipped++;
                }
            } else {
                skipped++;
            }
            try {
                Thread.sleep(DELAY_BETWEEN_CALLS_MS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        log.info("finished AI explanations for scan {}: {} explained, {} skipped", scanId, explained, skipped);
    }
}
