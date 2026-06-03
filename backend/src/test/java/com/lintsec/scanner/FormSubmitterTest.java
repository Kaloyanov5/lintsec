package com.lintsec.scanner;

import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.crawler.FormField;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class FormSubmitterTest {

    @Test
    void includesSubmitControlAndPutsPayloadInTargetField() {
        DiscoveredForm form = new DiscoveredForm(
                "https://target.test/q", "GET",
                List.of(new FormField("name", "text", "")),
                new FormField("Submit", "submit", "Go"),
                "https://target.test/q");

        Map<String, String> data =
                FormSubmitter.buildSubmissionData(form, "name", "PAYLOAD", Map.of());

        assertEquals("PAYLOAD", data.get("name"));
        assertEquals("Go", data.get("Submit"));
    }

    @Test
    void submitControlFallsBackToNameWhenValueBlank() {
        DiscoveredForm form = new DiscoveredForm(
                "https://target.test/q", "POST",
                List.of(new FormField("name", "text", "")),
                new FormField("Submit", "submit", ""),
                "https://target.test/q");

        Map<String, String> data =
                FormSubmitter.buildSubmissionData(form, "name", "P", Map.of());
        assertEquals("Submit", data.get("Submit"));
    }

    @Test
    void freshHiddenValuesOverrideCrawlTimeValues() {
        DiscoveredForm form = new DiscoveredForm(
                "https://target.test/csrf", "POST",
                List.of(
                        new FormField("password_new", "password", ""),
                        new FormField("user_token", "hidden", "STALE0000")),
                new FormField("Change", "submit", "Change"),
                "https://target.test/csrf");

        Map<String, String> data = FormSubmitter.buildSubmissionData(
                form, "password_new", "PAYLOAD", Map.of("user_token", "FRESH9999"));

        assertEquals("PAYLOAD", data.get("password_new"));
        assertEquals("FRESH9999", data.get("user_token"));
        assertEquals("Change", data.get("Change"));
    }

    @Test
    void imageSubmitControlSendsXandYCoordinates() {
        DiscoveredForm form = new DiscoveredForm(
                "https://target.test/i", "POST",
                List.of(new FormField("name", "text", "")),
                new FormField("go", "image", ""),
                "https://target.test/i");

        Map<String, String> data =
                FormSubmitter.buildSubmissionData(form, "name", "P", Map.of());
        assertEquals("1", data.get("go.x"));
        assertEquals("1", data.get("go.y"));
        assertFalse(data.containsKey("go"));
    }

    @Test
    void tokenlessFormGetsFillersAndSubmitControl() {
        // The common path: no fresh values supplied; non-target fields get benign fillers
        // and the submit control is still appended.
        DiscoveredForm form = new DiscoveredForm(
                "https://target.test/contact", "POST",
                List.of(
                        new FormField("name", "text", ""),
                        new FormField("email", "email", "")),
                new FormField("Send", "submit", "Send"),
                "https://target.test/contact");

        Map<String, String> data =
                FormSubmitter.buildSubmissionData(form, "name", "PAYLOAD", Map.of());

        assertEquals("PAYLOAD", data.get("name"));
        assertEquals("lintsec@example.invalid", data.get("email")); // benign filler
        assertEquals("Send", data.get("Send"));
    }

    @Test
    void hiddenFieldAbsentFromFreshValuesKeepsDiscoveredDefault() {
        // Partial refresh: refresher returns some hidden fields but not this one; it must
        // fall through to its crawl-time discovered value, not get dropped or blanked.
        DiscoveredForm form = new DiscoveredForm(
                "https://target.test/edit", "POST",
                List.of(
                        new FormField("bio", "textarea", ""),
                        new FormField("section_id", "hidden", "42")),
                new FormField("Save", "submit", "Save"),
                "https://target.test/edit");

        Map<String, String> data =
                FormSubmitter.buildSubmissionData(form, "bio", "PAYLOAD", Map.of());

        assertEquals("PAYLOAD", data.get("bio"));
        assertEquals("42", data.get("section_id")); // discovered default preserved
    }
}
