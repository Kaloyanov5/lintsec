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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public final class ErrorBasedSqliModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(ErrorBasedSqliModule.class);

    private record SqlErrorPattern(
            String engineName,
            Pattern pattern
    ) {}

    private static final List<SqlErrorPattern> SQL_ERROR_PATTERNS = List.of(
            new SqlErrorPattern("MySQL",
                    Pattern.compile("You have an error in your SQL syntax|MySQL server version")),
            new SqlErrorPattern("PostgreSQL",
                    Pattern.compile("PostgreSQL.*ERROR|pg_query\\(\\)|PSQLException")),
            new SqlErrorPattern("Oracle",
                    Pattern.compile("ORA-\\d{5}|Oracle.*Driver")),
            new SqlErrorPattern("SQL Server",
                    Pattern.compile("Microsoft (OLE DB Provider|SQL Server)|Unclosed quotation mark|SQLServer JDBC Driver")),
            new SqlErrorPattern("SQLite",
                    Pattern.compile("SQLite/JDBCDriver|unrecognized token:")),
            new SqlErrorPattern("Generic JDBC/Hibernate",
                    Pattern.compile("java\\.sql\\.SQL[A-Za-z]*Exception|org\\.hibernate\\.exception"))
    );

    @Override
    public String name() {
        return "error-based-sqli";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        String payload = PayloadCatalog.payloadFor(PayloadId.SQLI_SINGLE_QUOTE, "");

        for (String url : crawlResult.visitedUrls()) {
            List<Map.Entry<String, String>> params = UrlParams.parseQueryParameters(URI.create(url));
            if (params.isEmpty()) continue;

            for (Map.Entry<String, String> entry : params) {
                String paramName = entry.getKey();
                String mutatedUrl = UrlParams.replaceQueryParameters(url, paramName, payload);

                Connection.Response resp;
                try {
                    resp = Jsoup.connect(mutatedUrl)
                            .userAgent(context.userAgent())
                            .timeout(context.timeoutMs())
                            .method(Connection.Method.GET)
                            .ignoreHttpErrors(true)
                            .followRedirects(true)
                            .execute();
                    log.debug("fetched URL: {} with status {}", url, resp.statusCode());
                } catch (Exception e) {
                    log.warn("failed to fetch URL: {}", url, e);
                    continue;
                }

                String body = resp.body();
                for (SqlErrorPattern pattern : SQL_ERROR_PATTERNS) {
                    Matcher matcher = pattern.pattern.matcher(body);
                    if (matcher.find()) {
                        findings.add(new ScanFinding(
                                "Error-based SQL injection via parameter: " + paramName,
                                Severity.HIGH,
                                name(),
                                new FindingLocation(url, paramName),
                                "A query parameter is concatenated into a SQL query without parameterization. An attacker can inject SQL fragments to read arbitrary tables, bypass authentication, modify data, or execute database-level commands depending on the engine and the DB user's privileges.",
                                "Use parameterized queries (prepared statements) for every SQL query that includes user input. In JDBC: PreparedStatement with ? placeholders. In JPA: query parameters (':paramName' or positional). Never concatenate input into query strings.",
                                PayloadId.SQLI_SINGLE_QUOTE,
                                "Database error signature for " + pattern.engineName + " matched at offset " + matcher.start()
                        ));
                        break;
                    }
                }
            }
        }

        return findings;
    }
}
