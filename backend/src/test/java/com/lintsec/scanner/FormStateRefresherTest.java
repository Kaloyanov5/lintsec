package com.lintsec.scanner;

import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.crawler.FormField;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FormStateRefresherTest {

    // A token-bearing form as the crawler first saw it (stale token value).
    private static DiscoveredForm staleForm() {
        return new DiscoveredForm(
                "https://target.test/csrf",
                "POST",
                List.of(
                        new FormField("password_new", "password", ""),
                        new FormField("user_token", "hidden", "STALE0000")
                ),
                new FormField("Change", "submit", "Change"),
                "https://target.test/csrf");
    }

    @Test
    void hasTokenFieldDetectsToken() {
        assertTrue(FormStateRefresher.hasTokenField(staleForm()));
        DiscoveredForm noToken = new DiscoveredForm(
                "https://target.test/x", "POST",
                List.of(new FormField("q", "text", "")), null, "https://target.test/x");
        assertFalse(FormStateRefresher.hasTokenField(noToken));
    }

    @Test
    void extractFreshValuesReturnsFreshHiddenValuesForMatchingForm() {
        // Re-fetched page: SAME form signature (method+action+sorted field names) but a NEW token.
        Document refetched = Jsoup.parse("""
            <form method="post" action="https://target.test/csrf">
              <input type="password" name="password_new">
              <input type="hidden" name="user_token" value="FRESH9999">
              <input type="submit" name="Change" value="Change">
            </form>
            """, "https://target.test/csrf");

        Optional<Map<String, String>> fresh =
                FormStateRefresher.extractFreshValues(refetched, staleForm());

        assertTrue(fresh.isPresent());
        assertEquals("FRESH9999", fresh.get().get("user_token"));
        assertFalse(fresh.get().containsKey("password_new"));
    }

    @Test
    void extractFreshValuesEmptyWhenNoMatchingForm() {
        Document refetched = Jsoup.parse("""
            <form method="post" action="https://target.test/OTHER">
              <input type="hidden" name="user_token" value="FRESH9999">
            </form>
            """, "https://target.test/csrf");

        assertTrue(FormStateRefresher.extractFreshValues(refetched, staleForm()).isEmpty());
    }
}
