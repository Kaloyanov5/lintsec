package com.lintsec.controller;

import com.lintsec.domain.Scan;
import com.lintsec.dto.FindingResponse;
import com.lintsec.dto.ScanCreateRequest;
import com.lintsec.dto.ScanResponse;
import com.lintsec.exception.NotFoundException;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanService scanService;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final SseEmitterRegistry sseRegistry;

    public ScanController(
            ScanService scanService,
            ScanRepository scanRepository,
            FindingRepository findingRepository,
            SseEmitterRegistry sseRegistry
    ) {
        this.scanService = scanService;
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.sseRegistry = sseRegistry;
    }

    @PostMapping
    public ResponseEntity<ScanResponse> create(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @Valid @RequestBody ScanCreateRequest req
    ) {
        Scan scan = scanService.createScan(principal.id(), req);
        scanService.runScanAsync(scan.getId());
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
