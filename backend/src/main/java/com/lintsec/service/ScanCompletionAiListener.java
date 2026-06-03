package com.lintsec.service;

import com.lintsec.domain.Finding;
import com.lintsec.domain.Severity;
import com.lintsec.domain.VulnerabilityType;
import com.lintsec.dto.ScanEvent;
import com.lintsec.repository.FindingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

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

    /**
     * Findings are displayed collapsed into one issue per {@code (type, severity, title)} (see
     * {@code FindingGrouper}). The AI explanation is identical within a group, so we explain once
     * per group and fan the text out to every member — not once per finding. Mirrors the grouper's
     * key so each displayed group gets exactly one explanation.
     */
    private record GroupKey(VulnerabilityType type, Severity severity, String title) {
        static GroupKey of(Finding f) {
            return new GroupKey(f.getVulnerabilityType(), f.getSeverity(), f.getTitle());
        }
    }

    @EventListener
    @Async
    public void onScanComplete(ScanEvent event) {
        if (event.type() != ScanEvent.EventType.SCAN_COMPLETE) return;
        Long scanId = event.scanId();
        List<Finding> scanFindings = findingRepository.findByScanIdOrderBySeverityAscCreatedAtAsc(scanId);

        Map<GroupKey, List<Finding>> groups = scanFindings.stream()
                .collect(Collectors.groupingBy(GroupKey::of, LinkedHashMap::new, Collectors.toList()));

        log.info("starting AI explanations for scan {} ({} findings, {} groups)",
                scanId, scanFindings.size(), groups.size());

        int explained = 0;
        int skipped = 0;
        for (List<Finding> members : groups.values()) {
            Optional<String> text = explanationService.explain(members.getFirst());
            if (text.isPresent()) {
                try {
                    members.forEach(f -> f.setAiExplanation(text.get()));
                    findingRepository.saveAll(members);
                    explained++;
                } catch (Exception e) {
                    log.warn("failed to save AI explanation for group {}: {}",
                            GroupKey.of(members.getFirst()), e.getMessage());
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
        log.info("finished AI explanations for scan {}: {} groups explained, {} skipped",
                scanId, explained, skipped);
    }
}
