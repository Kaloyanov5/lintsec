package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.*;
import org.jsoup.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Active module: probes URL params and form fields for path traversal / local file inclusion
 * by requesting a deep ../ path to a known system file and matching that file's content
 * signature in the response.
 */
@Component
public final class PathTraversalModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(PathTraversalModule.class);

    private record FileSignature(PayloadId payload, Pattern pattern) {}

    private static final List<FileSignature> SIGNATURES = List.of(
            new FileSignature(PayloadId.PATH_TRAVERSAL_UNIX,
                    Pattern.compile("root:.*:0:0:")),
            new FileSignature(PayloadId.PATH_TRAVERSAL_WINDOWS,
                    Pattern.compile("\\[(fonts|extensions|mci extensions)\\]", Pattern.CASE_INSENSITIVE))
    );

    private static final List<PayloadId> PAYLOADS =
            List.of(PayloadId.PATH_TRAVERSAL_UNIX, PayloadId.PATH_TRAVERSAL_WINDOWS);

    @Override
    public String name() {
        return "path-traversal";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        for (String url : crawlResult.visitedUrls()) {
            List<Map.Entry<String, String>> params = UrlParams.parseQueryParameters(URI.create(url));
            for (Map.Entry<String, String> entry : params) {
                probeParam(url, entry.getKey(), context).ifPresent(findings::add);
            }
        }

        for (DiscoveredForm form : crawlResult.forms()) {
            for (String field : FormSubmitter.fuzzableFields(form)) {
                probeFormField(form, field, context).ifPresent(findings::add);
            }
        }
        return findings;
    }

    private Optional<ScanFinding> probeParam(String url, String paramName, ScanContext context) {
        for (PayloadId payloadId : PAYLOADS) {
            String mutatedUrl = UrlParams.replaceQueryParameters(
                    url, paramName, PayloadCatalog.payloadFor(payloadId, ""));
            Connection.Response resp;
            try {
                resp = context.openConnection(mutatedUrl)
                        .method(Connection.Method.GET)
                        .ignoreHttpErrors(true)
                        .followRedirects(false)
                        .ignoreContentType(true)
                        .execute();
            } catch (Exception e) {
                log.warn("path-traversal param probe failed for {}: {}", mutatedUrl, e.getMessage());
                continue;
            }
            Optional<ScanFinding> finding = detect(resp.body())
                    .map(matched -> finding(new FindingLocation(url, paramName), "parameter: " + paramName, matched));
            if (finding.isPresent()) return finding;
        }
        return Optional.empty();
    }

    private Optional<ScanFinding> probeFormField(DiscoveredForm form, String field, ScanContext context) {
        for (PayloadId payloadId : PAYLOADS) {
            Optional<Connection.Response> respOpt =
                    FormSubmitter.submit(form, field, PayloadCatalog.payloadFor(payloadId, ""), context, true);
            if (respOpt.isEmpty()) continue;
            Optional<ScanFinding> finding = detect(respOpt.get().body())
                    .map(matched -> finding(new FindingLocation(form.action(), field), "form field: " + field, matched));
            if (finding.isPresent()) return finding;
        }
        return Optional.empty();
    }

    /** Package-private for unit testing. Returns the matched file's payload id, or empty. */
    static Optional<PayloadId> detect(String body) {
        if (body == null) return Optional.empty();
        for (FileSignature sig : SIGNATURES) {
            if (sig.pattern().matcher(body).find()) return Optional.of(sig.payload());
        }
        return Optional.empty();
    }

    private ScanFinding finding(FindingLocation location, String vector, PayloadId matched) {
        return new ScanFinding(
                "Path traversal / local file inclusion via " + vector,
                Severity.HIGH,
                name(),
                location,
                "A parameter is used to build a filesystem path without validation, letting an attacker traverse out of the intended directory (../../) and read arbitrary files such as /etc/passwd, application source, or configuration containing secrets. Depending on how the file is consumed this can escalate to remote code execution.",
                "Never build filesystem paths from raw user input. Map user-supplied identifiers to an allow-list of known files, or resolve the canonical path and verify it stays within an expected base directory. Reject input containing path separators or '..'.",
                matched,
                "Response to a traversal payload in " + vector + " contained a system-file signature (" + matched.name() + ").");
    }
}
