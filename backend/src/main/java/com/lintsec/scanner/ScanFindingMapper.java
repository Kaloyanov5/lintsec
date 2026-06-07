package com.lintsec.scanner;

import com.lintsec.domain.Finding;
import com.lintsec.domain.Scan;
import com.lintsec.domain.VulnerabilityType;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public final class ScanFindingMapper {
    private final ObjectMapper objectMapper;

    public ScanFindingMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public Finding toEntity(ScanFinding source, Scan scan) {
        Finding finding = new Finding();
        finding.setScan(scan);
        finding.setVulnerabilityType(mapModuleToType(source.module()));
        finding.setSeverity(source.severity());
        finding.setTitle(source.title());
        finding.setDescription(source.description());
        finding.setRemediation(source.remediation());
        finding.setEvidenceJson(serializeEvidence(source));
        finding.setPayloadRef(source.evidenceRef() != null ? source.evidenceRef().name() : null);
        return finding;
    }

    private static VulnerabilityType mapModuleToType(String moduleName) {
        return switch (moduleName) {
            case "missing-security-headers" -> VulnerabilityType.SECURITY_HEADERS;
            case "sensitive-info-disclosure" -> VulnerabilityType.SENSITIVE_DATA;
            case "open-redirect" -> VulnerabilityType.OPEN_REDIRECT;
            case "reflected-xss" -> VulnerabilityType.XSS;
            case "error-based-sqli" -> VulnerabilityType.SQL_INJECTION;
            case "cookie-security" -> VulnerabilityType.COOKIE_SECURITY;
            case "cors-misconfig"  -> VulnerabilityType.CORS;
            case "missing-csrf-token" -> VulnerabilityType.CSRF;
            case "directory-listing" -> VulnerabilityType.DIRECTORY_LISTING;
            case "http-method-tampering" -> VulnerabilityType.INSECURE_HTTP_METHOD;
            case "path-traversal" -> VulnerabilityType.PATH_TRAVERSAL;
            case "command-injection" -> VulnerabilityType.COMMAND_INJECTION;
            case "mixed-content" -> VulnerabilityType.MIXED_CONTENT;
            case "missing-sri" -> VulnerabilityType.MISSING_SRI;
            default -> throw new IllegalStateException("unknown module: " + moduleName);
        };
    }

    private String serializeEvidence(ScanFinding source) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("url", source.location().url());
        evidence.put("parameter", source.location().parameter());
        evidence.put("note", source.evidenceNote());
        try {
            return objectMapper.writeValueAsString(evidence);
        } catch (JacksonException e) {
            throw new IllegalStateException("failed to serialize evidence", e);
        }
    }
}
