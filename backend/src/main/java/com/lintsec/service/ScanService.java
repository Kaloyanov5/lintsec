package com.lintsec.service;

import com.lintsec.crawler.AuthSession;
import com.lintsec.crawler.CrawlConfig;
import com.lintsec.crawler.CrawlResult;
import com.lintsec.crawler.Crawler;
import com.lintsec.domain.Finding;
import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanPage;
import com.lintsec.domain.ScanStatus;
import com.lintsec.dto.ScanCreateRequest;
import com.lintsec.dto.ScanEvent;
import com.lintsec.exception.NotFoundException;
import com.lintsec.repository.FindingRepository;
import com.lintsec.repository.ScanPageRepository;
import com.lintsec.repository.ScanRepository;
import com.lintsec.repository.UserRepository;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScanFindingMapper;
import com.lintsec.scanner.Scanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class ScanService {
    private static final int DEFAULT_TIMEOUT_MS = 10_000;
    private static final String DEFAULT_USER_AGENT = "LintSec-Scanner/1.0";
    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanRepository scanRepository;
    private final ScanPageRepository scanPageRepository;
    private final FindingRepository findingRepository;
    private final UserRepository userRepository;
    private final Scanner scanner;
    private final ScanFindingMapper mapper;
    private final ApplicationEventPublisher events;

    public ScanService(
            ScanRepository scanRepository,
           ScanPageRepository scanPageRepository,
           FindingRepository findingRepository,
           UserRepository userRepository,
           Scanner scanner,
           ScanFindingMapper mapper,
            ApplicationEventPublisher events
    ) {
        this.scanRepository = scanRepository;
        this.scanPageRepository = scanPageRepository;
        this.findingRepository = findingRepository;
        this.userRepository = userRepository;
        this.scanner = scanner;
        this.mapper = mapper;
        this.events = events;
    }

    @Async
    public void runScanAsync(Long scanId) {
        try {
            runScan(scanId);
        } catch (Exception e) {
            log.error("uncaught error in async scan {}", scanId, e);
        }
    }

    public void runScan(Long scanId) {
        Optional<Scan> optionalScan = scanRepository.findById(scanId);
        if (optionalScan.isEmpty()) throw new NotFoundException("scan does not exist");
        Scan scan = optionalScan.get();
        if (!scan.isOwnershipConfirmed()) throw new IllegalStateException("ownership not confirmed");
        if (scan.getStatus() != ScanStatus.PENDING) throw new IllegalStateException("only pending scan can be ran");

        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(Instant.now());
        scanRepository.save(scan);
        events.publishEvent(new ScanEvent(scanId, ScanEvent.EventType.STARTED,
                0, 0, null));

        try {
            CrawlConfig crawlConfig = new CrawlConfig(
                    scan.getMaxDepth(),
                    scan.getMaxPages(),
                    DEFAULT_TIMEOUT_MS,
                    scan.getRequestDelayMs(),
                    DEFAULT_USER_AGENT,
                    scan.isIgnoreRobots(),
                    AuthSession.anonymous()
            );
            ScanContext scanContext = new ScanContext(crawlConfig.userAgent(), crawlConfig.timeoutMs(), true);
            CrawlResult result = new Crawler(crawlConfig).crawl(scan.getTargetUrl());
            List<ScanPage> scanPages = result.visitedUrls().stream().map(url -> {
                ScanPage scanPage = new ScanPage();
                scanPage.setScan(scan);
                scanPage.setUrl(url);
                scanPage.setDepth(0);
                scanPage.setStatusCode(null);
                scanPage.setTitle(null);
                return scanPage;
            }).toList();
            scanPageRepository.saveAll(scanPages);
            scan.setPagesCrawled(result.visitedUrls().size());
            events.publishEvent(new ScanEvent(scanId, ScanEvent.EventType.CRAWL_COMPLETE,
                    result.visitedUrls().size(), 0, null));
            List<ScanFinding> raw = scanner.scan(result, scanContext);
            List<Finding> findings = raw.stream().map(sf -> mapper.toEntity(sf, scan)).toList();
            findingRepository.saveAll(findings);

            scan.setStatus(ScanStatus.COMPLETE);
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);
            events.publishEvent(new ScanEvent(scanId, ScanEvent.EventType.SCAN_COMPLETE,
                    result.visitedUrls().size(), findings.size(), null));
        } catch (Exception e) {
            log.error("scan {} failed", scanId, e);
            scan.setStatus(ScanStatus.FAILED);
            if (e.getMessage() != null) scan.setErrorMessage(truncate(e.getMessage(), 1000));
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);
            events.publishEvent(new ScanEvent(scanId, ScanEvent.EventType.FAILED,
                    scan.getPagesCrawled(),    // partial value if we got that far
                    0,                          // findings list never built on failure path
                    e.getMessage()));
        }
    }

    public Scan createScan(Long userId, ScanCreateRequest req) {
        Scan scan = new Scan();
        scan.setUser(userRepository.getReferenceById(userId));   // lazy FK ref, no SELECT
        scan.setTargetUrl(req.targetUrl());
        scan.setOwnershipConfirmed(req.ownershipConfirmed());
        scan.setMaxDepth(req.maxDepth());
        scan.setMaxPages(req.maxPages());
        scan.setRequestDelayMs(req.requestDelayMs());
        scan.setIgnoreRobots(req.ignoreRobots());
        // status defaults to PENDING via entity initializer
        return scanRepository.save(scan);
    }

    private static String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) : s;
    }
}
