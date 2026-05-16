package com.lintsec.scanner;

import com.lintsec.crawler.CrawlResult;

import java.util.List;

public interface ScannerModule {
    String name();
    List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context);
}
