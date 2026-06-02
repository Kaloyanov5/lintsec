package com.lintsec.controller;

import com.lintsec.domain.Finding;
import com.lintsec.domain.Scan;
import com.lintsec.domain.Severity;
import com.lintsec.dto.FindingGroupResponse;
import com.lintsec.dto.FindingResponse;
import com.lintsec.dto.ScanCreateRequest;
import com.lintsec.dto.ScanExport;
import com.lintsec.dto.ScanResponse;
import com.lintsec.crawler.LoginConfig;
import com.lintsec.exception.NotFoundException;
import com.lintsec.report.FindingGrouper;
import com.lintsec.report.ScanReportPdfRenderer;
import com.lintsec.repository.FindingRepository;
import com.lintsec.repository.ScanRepository;
import com.lintsec.security.AppUserPrincipal;
import com.lintsec.service.ScanService;
import com.lintsec.sse.SseEmitterRegistry;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private static final DateTimeFormatter FILENAME_DATE = DateTimeFormatter.BASIC_ISO_DATE;

    private final ScanService scanService;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final SseEmitterRegistry sseRegistry;
    private final FindingGrouper findingGrouper;
    private final ScanReportPdfRenderer pdfRenderer;

    public ScanController(
            ScanService scanService,
            ScanRepository scanRepository,
            FindingRepository findingRepository,
            SseEmitterRegistry sseRegistry,
            FindingGrouper findingGrouper,
            ScanReportPdfRenderer pdfRenderer
    ) {
        this.scanService = scanService;
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.sseRegistry = sseRegistry;
        this.findingGrouper = findingGrouper;
        this.pdfRenderer = pdfRenderer;
    }

    @PostMapping
    public ResponseEntity<ScanResponse> create(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @Valid @RequestBody ScanCreateRequest req
    ) {
        Scan scan = scanService.createScan(principal.id(), req);
        LoginConfig loginConfig = scanService.toLoginConfig(req.auth());
        scanService.runScanAsync(scan.getId(), loginConfig);
        return ResponseEntity.status(HttpStatus.CREATED).body(ScanResponse.from(scan));
    }

    @GetMapping
    public Page<ScanResponse> list(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable
    ) {
        return scanRepository.findByUserIdOrderByCreatedAtDesc(principal.id(), pageable)
                .map(ScanResponse::from);
    }

    @GetMapping("/{id}")
    public ScanResponse get(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @PathVariable Long id
    ) {
        Scan scan = scanRepository.findByIdAndUserId(id, principal.id())
                .orElseThrow(() -> new NotFoundException("scan not found"));
        return ScanResponse.from(scan);
    }

    @GetMapping("/{id}/findings")
    public List<FindingResponse> findings(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @PathVariable Long id
    ) {
        scanRepository.findByIdAndUserId(id, principal.id())
                .orElseThrow(() -> new NotFoundException("scan not found"));
        return findingRepository.findByScanIdOrderBySeverityAscCreatedAtAsc(id)
                .stream().map(FindingResponse::from).toList();
    }

    @GetMapping("/{id}/findings/grouped")
    public List<FindingGroupResponse> groupedFindings(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @PathVariable Long id
    ) {
        scanRepository.findByIdAndUserId(id, principal.id())
                .orElseThrow(() -> new NotFoundException("scan not found"));
        return findingGrouper.group(findingRepository.findByScanIdOrderBySeverityAscCreatedAtAsc(id));
    }

    @GetMapping(value = "/{id}/export.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ScanExport> exportJson(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @PathVariable Long id
    ) {
        ScanExport export = buildExport(principal.id(), id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment(id, "json"))
                .body(export);
    }

    @GetMapping(value = "/{id}/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> exportPdf(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @PathVariable Long id
    ) {
        ScanExport export = buildExport(principal.id(), id);
        byte[] pdf = pdfRenderer.render(export);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment(id, "pdf"))
                .body(pdf);
    }

    private ScanExport buildExport(Long userId, Long scanId) {
        Scan scan = scanRepository.findByIdAndUserId(scanId, userId)
                .orElseThrow(() -> new NotFoundException("scan not found"));
        List<Finding> findings = findingRepository.findByScanIdOrderBySeverityAscCreatedAtAsc(scanId);
        List<FindingGroupResponse> groups = findingGrouper.group(findings);

        Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
        for (Severity sev : Severity.values()) severityCounts.put(sev, 0);
        for (FindingGroupResponse group : groups) {
            severityCounts.merge(group.severity(), 1, Integer::sum);
        }
        int totalFindings = groups.stream().mapToInt(FindingGroupResponse::count).sum();

        return new ScanExport(ScanResponse.from(scan), severityCounts, totalFindings, groups);
    }

    private static String attachment(Long scanId, String ext) {
        String filename = "lintsec-scan-" + scanId + "-"
                + LocalDate.now(ZoneOffset.UTC).format(FILENAME_DATE) + "." + ext;
        return "attachment; filename=\"" + filename + "\"";
    }

    @GetMapping(value = "/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter events(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @PathVariable Long id
    ) {
        scanRepository.findByIdAndUserId(id, principal.id())
                .orElseThrow(() -> new NotFoundException("scan not found"));
        return sseRegistry.register(id);
    }
}
