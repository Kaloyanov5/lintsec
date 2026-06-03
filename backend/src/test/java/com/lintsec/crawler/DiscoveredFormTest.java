package com.lintsec.crawler;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class DiscoveredFormTest {

    // The signature must identify the same form across re-fetches even though its hidden
    // token value changes between GETs. FormStateRefresher relies on this invariant to match
    // a re-fetched form back to the one the crawler originally discovered.
    @Test
    void signatureIgnoresFieldValuesAndOrder() {
        DiscoveredForm stale = new DiscoveredForm(
                "https://t.test/csrf", "POST",
                List.of(
                        new FormField("user_token", "hidden", "STALE0000"),
                        new FormField("password_new", "password", "")),
                new FormField("Change", "submit", "Change"),
                "https://t.test/csrf");

        DiscoveredForm fresh = new DiscoveredForm(
                "https://t.test/csrf", "POST",
                List.of(
                        new FormField("password_new", "password", ""),     // different order
                        new FormField("user_token", "hidden", "FRESH9999")), // different value
                new FormField("Change", "submit", "Change"),
                "https://t.test/csrf");

        assertEquals(stale.signature(), fresh.signature());
    }

    @Test
    void signatureDiffersOnMethodActionOrFieldNames() {
        DiscoveredForm base = new DiscoveredForm(
                "https://t.test/a", "POST",
                List.of(new FormField("q", "text", "")), null, "https://t.test/a");

        DiscoveredForm differentAction = new DiscoveredForm(
                "https://t.test/b", "POST",
                List.of(new FormField("q", "text", "")), null, "https://t.test/b");
        DiscoveredForm differentField = new DiscoveredForm(
                "https://t.test/a", "POST",
                List.of(new FormField("other", "text", "")), null, "https://t.test/a");

        assertNotEquals(base.signature(), differentAction.signature());
        assertNotEquals(base.signature(), differentField.signature());
    }
}
