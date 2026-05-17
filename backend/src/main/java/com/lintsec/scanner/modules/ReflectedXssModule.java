package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.*;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.*;

@Component
public final class ReflectedXssModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(ReflectedXssModule.class);

    @Override
    public String name() {
        return "reflected-xss";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        String nonce = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String canary = PayloadCatalog.payloadFor(PayloadId.XSS_CANARY_REFLECTED, nonce);

        for (String url : crawlResult.visitedUrls()) {
            List<Map.Entry<String, String>> params = UrlParams.parseQueryParameters(URI.create(url));
            if (params.isEmpty()) continue;

            for (Map.Entry<String, String> entry : params) {
                String paramName = entry.getKey();
                String mutatedUrl = UrlParams.replaceQueryParameters(url, paramName, canary);

                Connection.Response resp;
                try {
                    resp = Jsoup.connect(mutatedUrl)
                            .userAgent(context.userAgent())
                            .timeout(context.timeoutMs())
                            .method(Connection.Method.GET)
                            .ignoreHttpErrors(true)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();
                    log.debug("fetched URL: {} with status {}", url, resp.statusCode());
                } catch (Exception e) {
                    log.warn("failed to fetch URL: {}", url, e);
                    continue;
                }

                String body = resp.body();
                int offset = body.indexOf(canary);
                if (offset >= 0) {
                    findings.add(new ScanFinding(
                            "Reflected XSS via parameter: " + paramName,
                            Severity.HIGH,
                            name(),
                            new FindingLocation(url, paramName),
                            "A query parameter is reflected into the response HTML without encoding. An attacker can craft a link containing JavaScript that executes in the victim's browser, leading to session theft, credential harvesting, or arbitrary actions on the user's behalf.",
                            "Context-appropriate output encoding (HTML-encode for tag content, attribute-encode for attribute values, JS-encode for script context). Most templating engines do this by default — ensure unsafe APIs like Thymeleaf's th:utext or React's dangerouslySetInnerHTML are not used with user input.",
                            PayloadId.XSS_CANARY_REFLECTED,
                            "Canary string reflected unencoded in response body at offset " + offset + "."
                    ));
                }
            }
        }

        return findings;
    }
}
