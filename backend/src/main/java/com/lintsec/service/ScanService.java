package com.lintsec.service;

import com.lintsec.crawler.AuthSession;
import com.lintsec.crawler.CancellationToken;
import com.lintsec.crawler.CrawlConfig;
import com.lintsec.crawler.CrawlResult;
import com.lintsec.crawler.Crawler;
import com.lintsec.crawler.FormLoginAuthenticator;
import com.lintsec.crawler.LoginConfig;
import com.lintsec.crawler.TargetGuard;
import com.lintsec.domain.Finding;
import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanPage;
import com.lintsec.domain.ScanStatus;
import com.lintsec.dto.ScanCreateRequest;
import com.lintsec.dto.ScanEvent;
import com.lintsec.dto.ScanStatsResponse;
import com.lintsec.exception.BadRequestException;
import com.lintsec.exception.ConflictException;
import com.lintsec.exception.NotFoundException;
import com.lintsec.repository.FindingRepository;
import com.lintsec.repository.ScanPageRepository;
import com.lintsec.repository.ScanRepository;
import com.lintsec.repository.UserRepository;
import com.lintsec.config.ScanProperties;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScanFindingMapper;
import com.lintsec.scanner.Scanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
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
    private final FormLoginAuthenticator authenticator;
    private final ScanCancellationRegistry cancellationRegistry;
    private final ScanProperties scanProperties;

    public ScanService(
            ScanRepository scanRepository,
           ScanPageRepository scanPageRepository,
           FindingRepository findingRepository,
           UserRepository userRepository,
           Scanner scanner,
           ScanFindingMapper mapper,
            ApplicationEventPublisher events,
            FormLoginAuthenticator authenticator,
            ScanCancellationRegistry cancellationRegistry,
            ScanProperties scanProperties
    ) {
        this.scanRepository = scanRepository;
        this.scanPageRepository = scanPageRepository;
        this.findingRepository = findingRepository;
        this.userRepository = userRepository;
        this.scanner = scanner;
        this.mapper = mapper;
        this.events = events;
        this.authenticator = authenticator;
        this.cancellationRegistry = cancellationRegistry;
        this.scanProperties = scanProperties;
    }

    @Async("scanExecutor")
    public void runScanAsync(Long scanId, LoginConfig loginConfig) {
        try {
            runScan(scanId, loginConfig);
        } catch (Exception e) {
            log.error("uncaught error in async scan {}", scanId, e);
        }
    }

    public void runScan(Long scanId, LoginConfig loginConfig) {
        Optional<Scan> optionalScan = scanRepository.findById(scanId);
        if (optionalScan.isEmpty()) throw new NotFoundException("scan does not exist");
        Scan scan = optionalScan.get();
        if (!scan.isOwnershipConfirmed()) throw new IllegalStateException("ownership not confirmed");
        if (scan.getStatus() != ScanStatus.PENDING) throw new IllegalStateException("only pending scan can be ran");

        // The token stops the scan on explicit cancel OR when the wall-clock deadline passes, so
        // the deadline is observed everywhere the loops already poll for cancellation.
        Instant deadline = Instant.now().plus(Duration.ofMinutes(scanProperties.maxDurationMinutes()));
        CancellationToken token = () -> cancellationRegistry.isRequested(scanId) || Instant.now().isAfter(deadline);

        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(Instant.now());
        scanRepository.save(scan);
        events.publishEvent(new ScanEvent(scanId, ScanEvent.EventType.STARTED,
                0, 0, null));

        try {
            if (token.isCancellationRequested()) {
                finalizeStopped(scan, 0, 0);
                return;
            }

            AuthSession authSession = AuthSession.anonymous();
            if (loginConfig != null) {
                authSession = authenticator.authenticate(loginConfig);  // throws AuthenticationException on failure
                scan.setAuthenticated(true);
                scanRepository.save(scan);
            }

            CrawlConfig crawlConfig = new CrawlConfig(
                    scan.getMaxDepth(),
                    scan.getMaxPages(),
                    DEFAULT_TIMEOUT_MS,
                    scan.getRequestDelayMs(),
                    DEFAULT_USER_AGENT,
                    scan.isIgnoreRobots(),
                    authSession
            );
            ScanContext scanContext = new ScanContext(
                    crawlConfig.userAgent(), crawlConfig.timeoutMs(), true, crawlConfig.authSession());
            CrawlResult result = new Crawler(crawlConfig).crawl(scan.getTargetUrl(), token);
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

            if (token.isCancellationRequested()) {
                finalizeStopped(scan, result.visitedUrls().size(), 0);
                return;
            }

            List<ScanFinding> raw = scanner.scan(result, scanContext, token);
            List<Finding> findings = raw.stream().map(sf -> mapper.toEntity(sf, scan)).toList();
            findingRepository.saveAll(findings);

            if (token.isCancellationRequested()) {
                finalizeStopped(scan, result.visitedUrls().size(), findings.size());
                return;
            }

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
        } finally {
            cancellationRegistry.clear(scanId);
        }
    }

    /**
     * Terminates a scan that the token stopped early. Distinguishes a user cancellation (→ CANCELLED)
     * from a wall-clock-deadline trip (→ FAILED with a timeout message), since the token fires for both.
     */
    private void finalizeStopped(Scan scan, int pagesCrawled, int findingsCount) {
        scan.setCompletedAt(Instant.now());
        if (cancellationRegistry.isRequested(scan.getId())) {
            scan.setStatus(ScanStatus.CANCELLED);
            scan.setCancelRequested(false);
            scanRepository.save(scan);
            events.publishEvent(new ScanEvent(scan.getId(), ScanEvent.EventType.CANCELLED,
                    pagesCrawled, findingsCount, null));
        } else {
            String message = "scan exceeded the maximum duration of "
                    + scanProperties.maxDurationMinutes() + " minutes";
            scan.setStatus(ScanStatus.FAILED);
            scan.setErrorMessage(message);
            scanRepository.save(scan);
            events.publishEvent(new ScanEvent(scan.getId(), ScanEvent.EventType.FAILED,
                    pagesCrawled, findingsCount, message));
        }
    }

    public Scan createScan(Long userId, ScanCreateRequest req) {
        if (!TargetGuard.isAllowed(req.targetUrl())) {
            throw new BadRequestException(
                    "target URL is not permitted: internal, loopback, and link-local addresses cannot be scanned");
        }
        ScanCreateRequest.AuthConfig auth = req.auth();
        if (auth != null && auth.loginUrl() != null && !auth.loginUrl().isBlank()
                && !TargetGuard.isAllowed(auth.loginUrl())) {
            throw new BadRequestException(
                    "login URL is not permitted: internal, loopback, and link-local addresses cannot be scanned");
        }

        long active = scanRepository.countByUserIdAndStatusIn(
                userId, List.of(ScanStatus.PENDING, ScanStatus.RUNNING));
        if (active >= scanProperties.maxConcurrentPerUser()) {
            throw new ConflictException(
                    "you already have " + active + " active scans (max "
                            + scanProperties.maxConcurrentPerUser() + "); wait for one to finish");
        }

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

    public Scan cancelScan(Long userId, Long scanId) {
        Scan scan = scanRepository.findByIdAndUserId(scanId, userId)
                .orElseThrow(() -> new NotFoundException("scan not found"));

        if (scan.getStatus() != ScanStatus.PENDING && scan.getStatus() != ScanStatus.RUNNING)
            throw new ConflictException("scan is not running");

        cancellationRegistry.request(scanId);
        scan.setCancelRequested(true);

        return scanRepository.save(scan);
    }

    @Transactional
    public void deleteScan(Long userId, Long scanId) {
        Scan scan = scanRepository.findByIdAndUserId(scanId, userId)
                .orElseThrow(() -> new NotFoundException("scan not found"));

        ScanStatus status = scan.getStatus();
        if (status == ScanStatus.PENDING || status == ScanStatus.RUNNING) {
            throw new ConflictException("cannot delete a running scan; cancel it first");
        }

        findingRepository.deleteByScanId(scanId);
        scanPageRepository.deleteByScanId(scanId);
        scanRepository.delete(scan);
    }

    @Transactional(readOnly = true)
    public ScanStatsResponse getStats(Long userId) {
        long totalScans = scanRepository.countByUserId(userId);
        long completedScans = scanRepository.countByUserIdAndStatus(userId, ScanStatus.COMPLETE);
        List<Object[]> severityRows = findingRepository.countBySeverityForUser(userId);
        return ScanStatsResponse.from(totalScans, completedScans, severityRows);
    }

    public LoginConfig toLoginConfig(ScanCreateRequest.AuthConfig auth) {
        if (auth == null) return null;
        return new LoginConfig(
                auth.loginUrl(),
                auth.usernameField(),
                auth.passwordField(),
                auth.username(),
                auth.password(),
                auth.successCheck(),
                auth.sessionCookie()
        );
    }

    private static String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) : s;
    }
}
