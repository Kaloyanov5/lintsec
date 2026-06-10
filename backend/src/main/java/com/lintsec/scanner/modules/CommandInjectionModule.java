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
 * Active module: probes URL params and form fields for OS command injection by appending a shell
 * metacharacter + a harmless read-only command ('id' on Unix, 'ver' on Windows) and matching the
 * command's output in the response. Output-based only — no blind/time-based detection.
 */
@Component
public final class CommandInjectionModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(CommandInjectionModule.class);

    private record Injection(PayloadId id, String payload) {}
    private record CmdSignature(PayloadId os, Pattern pattern) {}

    // Several Unix separators (the right one depends on how input is interpolated) plus Windows.
    private static final List<Injection> INJECTIONS = List.of(
            new Injection(PayloadId.CMDI_UNIX_ID, ";id"),
            new Injection(PayloadId.CMDI_UNIX_ID, "|id"),
            new Injection(PayloadId.CMDI_UNIX_ID, "&&id"),
            new Injection(PayloadId.CMDI_WINDOWS_VER, "& ver")
    );

    private static final List<CmdSignature> SIGNATURES = List.of(
            new CmdSignature(PayloadId.CMDI_UNIX_ID, Pattern.compile("uid=\\d+\\(.+\\)\\s+gid=\\d+")),
            new CmdSignature(PayloadId.CMDI_WINDOWS_VER, Pattern.compile("Windows \\[Version"))
    );

    @Override
    public String name() {
        return "command-injection";
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
        for (Injection inj : INJECTIONS) {
            String mutatedUrl = UrlParams.replaceQueryParameters(url, paramName, inj.payload());
            Connection.Response resp;
            try {
                resp = context.openConnection(mutatedUrl)
                        .method(Connection.Method.GET)
                        .ignoreHttpErrors(true)
                        .followRedirects(false)
                        .ignoreContentType(true)
                        .execute();
            } catch (Exception e) {
                log.warn("command-injection param probe failed for {}: {}", mutatedUrl, e.getMessage());
                continue;
            }
            Optional<ScanFinding> finding = detect(resp.body())
                    .map(matched -> finding(new FindingLocation(url, paramName), "parameter: " + paramName, matched));
            if (finding.isPresent()) return finding;
        }
        return Optional.empty();
    }

    private Optional<ScanFinding> probeFormField(DiscoveredForm form, String field, ScanContext context) {
        for (Injection inj : INJECTIONS) {
            Optional<Connection.Response> respOpt =
                    FormSubmitter.submit(form, field, inj.payload(), context, true);
            if (respOpt.isEmpty()) continue;
            Optional<ScanFinding> finding = detect(respOpt.get().body())
                    .map(matched -> finding(new FindingLocation(form.action(), field), "form field: " + field, matched));
            if (finding.isPresent()) return finding;
        }
        return Optional.empty();
    }

    /** Package-private for unit testing. Returns the matched OS payload id, or empty. */
    static Optional<PayloadId> detect(String body) {
        if (body == null) return Optional.empty();
        for (CmdSignature sig : SIGNATURES) {
            if (sig.pattern().matcher(body).find()) return Optional.of(sig.os());
        }
        return Optional.empty();
    }

    private ScanFinding finding(FindingLocation location, String vector, PayloadId matched) {
        return new ScanFinding(
                "OS command injection via " + vector,
                Severity.CRITICAL,
                name(),
                location,
                "A parameter is passed to a system shell without sanitization. By injecting shell metacharacters (;, |, &&) an attacker can run arbitrary operating-system commands on the server with the application's privileges — full host compromise in most cases.",
                "Never pass user input to a shell. Use language-native APIs or an argument array that bypasses the shell (e.g. ProcessBuilder with separate arguments). If a shell is unavoidable, validate input against a strict allow-list; do not rely on escaping.",
                matched,
                "Response to a command-injection payload in " + vector + " contained command output (" + matched.name() + ").");
    }
}
