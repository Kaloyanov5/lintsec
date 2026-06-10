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

@Component
public final class ErrorBasedSqliModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(ErrorBasedSqliModule.class);

    private record SqlErrorPattern(
            String engineName,
            java.util.regex.Pattern pattern
    ) {}

    private static final List<SqlErrorPattern> SQL_ERROR_PATTERNS = List.of(
            new SqlErrorPattern("MySQL",
                    java.util.regex.Pattern.compile("You have an error in your SQL syntax|MySQL server version")),
            new SqlErrorPattern("PostgreSQL",
                    java.util.regex.Pattern.compile("PostgreSQL.*ERROR|pg_query\\(\\)|PSQLException")),
            new SqlErrorPattern("Oracle",
                    java.util.regex.Pattern.compile("ORA-\\d{5}|Oracle.*Driver")),
            new SqlErrorPattern("SQL Server",
                    java.util.regex.Pattern.compile("Microsoft (OLE DB Provider|SQL Server)|Unclosed quotation mark|SQLServer JDBC Driver")),
            new SqlErrorPattern("SQLite",
                    java.util.regex.Pattern.compile("SQLite/JDBCDriver|unrecognized token:")),
            new SqlErrorPattern("Generic JDBC/Hibernate",
                    java.util.regex.Pattern.compile("java\\.sql\\.SQL[A-Za-z]*Exception|org\\.hibernate\\.exception"))
    );

    @Override
    public String name() {
        return "error-based-sqli";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        BaselineCache baselines = new BaselineCache(context);
        String broken = PayloadCatalog.payloadFor(PayloadId.SQLI_SINGLE_QUOTE, "");
        String balanced = PayloadCatalog.payloadFor(PayloadId.SQLI_BALANCED, "");

        for (String url : crawlResult.visitedUrls()) {
            List<Map.Entry<String, String>> params = UrlParams.parseQueryParameters(URI.create(url));
            if (params.isEmpty()) continue;

            for (Map.Entry<String, String> entry : params) {
                String paramName = entry.getKey();
                String brokenBody = fetchBody(context, UrlParams.replaceQueryParameters(url, paramName, broken));
                if (brokenBody == null) continue;
                String balancedBody = fetchBody(context, UrlParams.replaceQueryParameters(url, paramName, balanced));

                confirmInjection(baselines.forUrl(url), brokenBody, balancedBody == null ? "" : balancedBody)
                        .ifPresent(engine -> findings.add(
                                finding(new FindingLocation(url, paramName), "parameter: " + paramName, engine)));
            }
        }

        // Form vector: submit each discovered form with the single-quote payload in one field at a time.
        for (DiscoveredForm form : crawlResult.forms()) {
            for (String field : FormSubmitter.fuzzableFields(form)) {
                String brokenBody = FormSubmitter.submit(form, field, broken, context, true)
                        .map(Connection.Response::body).orElse(null);
                if (brokenBody == null) continue;
                String balancedBody = FormSubmitter.submit(form, field, balanced, context, true)
                        .map(Connection.Response::body).orElse("");

                confirmInjection(baselines.forForm(form), brokenBody, balancedBody)
                        .ifPresent(engine -> findings.add(
                                finding(new FindingLocation(form.action(), field), "form field: " + field, engine)));
            }
        }

        return findings;
    }

    private static String fetchBody(ScanContext context, String url) {
        try {
            return context.openConnection(url)
                    .method(Connection.Method.GET)
                    .ignoreHttpErrors(true)
                    .followRedirects(false)
                    .ignoreContentType(true)
                    .execute()
                    .body();
        } catch (Exception e) {
            log.warn("error-based-sqli fetch failed for {}: {}", url, e.getMessage());
            return null;
        }
    }

    /** First SQL-engine whose error signature is present in {@code body}, or empty. */
    static Optional<String> firstErrorEngine(String body) {
        if (body == null) return Optional.empty();
        for (SqlErrorPattern pattern : SQL_ERROR_PATTERNS) {
            if (pattern.pattern.matcher(body).find()) return Optional.of(pattern.engineName);
        }
        return Optional.empty();
    }

    /**
     * Confirms error-based SQLi: a DB error signature must appear under the broken ({@code '})
     * payload but NOT in the baseline (page errors anyway) nor under the balanced ({@code ''})
     * control (the quote isn't what broke the query). Returns the engine name on confirmation.
     * Pure — package-private for unit testing.
     */
    static Optional<String> confirmInjection(String baselineBody, String brokenBody, String balancedBody) {
        Optional<String> inBroken = firstErrorEngine(brokenBody);
        if (inBroken.isEmpty()) return Optional.empty();
        if (firstErrorEngine(baselineBody).isPresent()) return Optional.empty();
        if (firstErrorEngine(balancedBody).isPresent()) return Optional.empty();
        return inBroken;
    }

    private ScanFinding finding(FindingLocation location, String vector, String engine) {
        return new ScanFinding(
                "Error-based SQL injection via " + vector,
                Severity.HIGH,
                name(),
                location,
                "A parameter is concatenated into a SQL query without parameterization. An attacker can inject SQL fragments to read arbitrary tables, bypass authentication, modify data, or execute database-level commands depending on the engine and the DB user's privileges.",
                "Use parameterized queries (prepared statements) for every SQL query that includes user input. In JDBC: PreparedStatement with ? placeholders. In JPA: query parameters (':paramName' or positional). Never concatenate input into query strings.",
                PayloadId.SQLI_SINGLE_QUOTE,
                "A " + engine + " SQL error appeared only under the single-quote payload — absent from the "
                        + "baseline and the balanced '' control — indicating the quote broke the query."
        );
    }
}
