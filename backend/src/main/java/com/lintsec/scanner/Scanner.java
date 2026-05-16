package com.lintsec.scanner;

import com.lintsec.crawler.CrawlResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class Scanner {
    private static final Logger log = LoggerFactory.getLogger(Scanner.class);
    private final List<ScannerModule> modules;

    public Scanner(List<ScannerModule> modules) {
        this.modules = List.copyOf(modules);
    }

    public List<Finding> scan(CrawlResult crawlResult, ScanContext context) {
        log.info("starting scan: modules={} urls={} forms={}",
                this.modules.size(),
                crawlResult.visitedUrls().size(),
                crawlResult.forms().size()
        );

        List<Finding> findings = new ArrayList<>();
        int errorCount = 0;

        for (ScannerModule module : this.modules) {
            try {
                List<Finding> moduleFindings = module.scan(crawlResult, context);
                findings.addAll(moduleFindings);
                log.debug("module={} findings={}", module.name(), moduleFindings.size());
            } catch (Exception e) {
                errorCount++;
                log.error("module={} failed: {}", module.name(), e.getMessage(), e);
            }
        }

        log.info("scan complete: modules={} findings={} errors={}", modules.size(), findings.size(), errorCount);
        return findings;
    }
}
