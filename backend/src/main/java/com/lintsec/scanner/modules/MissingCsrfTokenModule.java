package com.lintsec.scanner.modules;

import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.crawler.FormField;
import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.CsrfTokens;
import com.lintsec.scanner.FindingLocation;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScannerModule;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Flags state-changing (POST) forms that carry no anti-CSRF token field.
 *
 * <p>Purely passive: it reasons over the forms the crawler already discovered, issuing no requests
 * of its own. This is a heuristic — a site may instead rely on SameSite cookies or a double-submit
 * cookie that isn't visible as a form field — so findings are MEDIUM and the description says so.
 */
@Component
public final class MissingCsrfTokenModule implements ScannerModule {

    @Override
    public String name() {
        return "missing-csrf-token";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        return crawlResult.forms().stream()
                .filter(form -> "POST".equalsIgnoreCase(form.method()))
                .filter(form -> !hasTokenField(form))
                .map(form -> new ScanFinding(
                        "POST form has no anti-CSRF token",
                        Severity.MEDIUM,
                        name(),
                        new FindingLocation(form.action(), null),
                        "A state-changing form submits over POST without any hidden anti-CSRF token field. If the endpoint relies on the session cookie alone, an attacker can host a page that auto-submits this form so the victim's browser performs the action with their credentials (Cross-Site Request Forgery). Note: this is a heuristic — protection may instead come from SameSite cookies or a double-submit cookie not visible in the form markup; confirm before treating as exploitable.",
                        "Include a per-session, unpredictable CSRF token as a hidden field in every state-changing form and validate it server-side. Most frameworks do this automatically (Spring Security's CsrfFilter, Django's {% csrf_token %}, Rails' authenticity_token). As defense-in-depth, set SameSite=Lax or Strict on the session cookie.",
                        null,
                        "POST form action '" + form.action() + "' contained no field whose name looks like a CSRF token."
                ))
                .toList();
    }

    private static boolean hasTokenField(DiscoveredForm form) {
        for (FormField field : form.fields()) {
            if (CsrfTokens.looksLikeTokenName(field.name())) return true;
        }
        return false;
    }
}
