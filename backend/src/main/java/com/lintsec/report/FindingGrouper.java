package com.lintsec.report;

import com.lintsec.domain.Finding;
import com.lintsec.domain.Severity;
import com.lintsec.dto.FindingGroupResponse;
import com.lintsec.dto.FindingInstanceResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Collapses the per-URL {@link Finding} rows a scanner emits into one issue per
 * {@code (vulnerabilityType, severity, title)}. The descriptive fields (description, remediation,
 * AI explanation) are identical within a group; the differing per-occurrence detail — parsed from
 * each row's {@code evidenceJson} — is carried as instances.
 *
 * <p>Read-time only: the scanner and database are untouched, so full per-row evidence is preserved.
 */
@Component
public final class FindingGrouper {

    private static final Logger log = LoggerFactory.getLogger(FindingGrouper.class);

    private final ObjectMapper objectMapper;

    public FindingGrouper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    private record GroupKey(com.lintsec.domain.VulnerabilityType type, Severity severity, String title) {}

    public List<FindingGroupResponse> group(List<Finding> findings) {
        Map<GroupKey, List<Finding>> grouped = new LinkedHashMap<>();
        for (Finding f : findings) {
            GroupKey key = new GroupKey(f.getVulnerabilityType(), f.getSeverity(), f.getTitle());
            grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(f);
        }

        List<FindingGroupResponse> result = new ArrayList<>(grouped.size());
        for (List<Finding> members : grouped.values()) {
            members.sort(Comparator.comparing(Finding::getCreatedAt,
                    Comparator.nullsLast(Comparator.naturalOrder())));
            Finding first = members.getFirst();

            // AI explanations are filled asynchronously, so an earlier-created row may still be null
            // while a sibling already has one — take the first non-null across the group.
            String aiExplanation = members.stream()
                    .map(Finding::getAiExplanation)
                    .filter(Objects::nonNull)
                    .findFirst()
                    .orElse(null);

            List<FindingInstanceResponse> instances = members.stream()
                    .map(this::toInstance)
                    .toList();

            result.add(new FindingGroupResponse(
                    first.getVulnerabilityType(),
                    first.getSeverity(),
                    first.getTitle(),
                    first.getDescription(),
                    first.getRemediation(),
                    aiExplanation,
                    members.size(),
                    instances
            ));
        }

        result.sort(Comparator.comparingInt((FindingGroupResponse g) -> g.severity().ordinal())
                .thenComparing(FindingGroupResponse::title));
        return result;
    }

    private FindingInstanceResponse toInstance(Finding f) {
        String url = null;
        String parameter = null;
        String note = null;
        String evidence = f.getEvidenceJson();
        if (evidence != null && !evidence.isBlank()) {
            try {
                JsonNode node = objectMapper.readTree(evidence);
                url = text(node, "url");
                parameter = text(node, "parameter");
                note = text(node, "note");
            } catch (RuntimeException e) {
                log.debug("could not parse evidenceJson for finding {}: {}", f.getId(), e.getMessage());
            }
        }
        return new FindingInstanceResponse(f.getId(), url, parameter, note, f.getPayloadRef(), f.getCreatedAt());
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && !v.isNull() ? v.asString() : null;
    }
}
