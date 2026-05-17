package com.lintsec.service;

import com.lintsec.crawler.CrawlConfig;
import com.lintsec.crawler.CrawlResult;
import com.lintsec.crawler.Crawler;
import com.lintsec.domain.Finding;
import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanPage;
import com.lintsec.domain.ScanStatus;
import com.lintsec.repository.FindingRepository;
import com.lintsec.repository.ScanPageRepository;
import com.lintsec.repository.ScanRepository;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScanFindingMapper;
import com.lintsec.scanner.Scanner;
import jakarta.persistence.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private final Scanner scanner;
    private final ScanFindingMapper mapper;

    public ScanService(
            ScanRepository scanRepository,
           ScanPageRepository scanPageRepository,
           FindingRepository findingRepository,
           Scanner scanner,
           ScanFindingMapper mapper
    ) {
        this.scanRepository = scanRepository;
        this.scanPageRepository = scanPageRepository;
        this.findingRepository = findingRepository;
        this.scanner = scanner;
        this.mapper = mapper;
    }

    public void runScan(Long scanId) {
        Optional<Scan> optionalScan = scanRepository.findById(scanId);
        if (optionalScan.isEmpty()) throw new EntityNotFoundException("scan does not exist");
        Scan scan = optionalScan.get();
        if (!scan.isOwnershipConfirmed()) throw new IllegalStateException("ownership not confirmed");
        if (scan.getStatus() != ScanStatus.PENDING) throw new IllegalStateException("only pending scan can be ran");

        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(Instant.now());
        scanRepository.save(scan);

        try {
            CrawlConfig crawlConfig = new CrawlConfig(
                    scan.getMaxDepth(),
                    scan.getMaxPages(),
                    DEFAULT_TIMEOUT_MS,
                    scan.getRequestDelayMs(),
                    DEFAULT_USER_AGENT
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
            List<ScanFinding> raw = scanner.scan(result, scanContext);
            List<Finding> findings = raw.stream().map(sf -> mapper.toEntity(sf, scan)).toList();
            findingRepository.saveAll(findings);

            scan.setStatus(ScanStatus.COMPLETE);
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);
        } catch (Exception e) {
            log.error("scan {} failed", scanId, e);
            scan.setStatus(ScanStatus.FAILED);
            if (e.getMessage() != null) scan.setErrorMessage(truncate(e.getMessage(), 1000));
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);
        }
    }

    private static String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) : s;
    }
}
