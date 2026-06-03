package com.lintsec.crawler;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.FormElement;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public final class FormExtractor {

    private FormExtractor() { }

    public static List<DiscoveredForm> extractForms(Document doc) {
        List<DiscoveredForm> forms = new ArrayList<>();
        for (FormElement form : doc.forms()) {
            String action = form.absUrl("action");
            // A blank/missing action means the form submits back to the page it lives on.
            if (action.isBlank()) action = doc.baseUri();
            // No resolvable submit target — we can't probe it, so skip.
            if (action.isBlank()) continue;
            String method = normalizeMethod(form.attr("method"));

            Elements fields = form.select("input, textarea, select");
            List<FormField> formFields = new ArrayList<>();
            FormField submitControl = null;
            for (Element field : fields) {
                String name = field.attr("name");
                if (name.isBlank()) {
                    continue;
                }
                String type = field.attr("type");
                if (type.isBlank()) {
                    type = "text";
                }
                // reset/button never submit the form; skip entirely.
                if (type.equalsIgnoreCase("reset") || type.equalsIgnoreCase("button")) {
                    continue;
                }
                // Capture the FIRST named submit/image control so we can re-send it
                // (many handlers run only when the submit key is present). Not a fuzzable field.
                if (type.equalsIgnoreCase("submit") || type.equalsIgnoreCase("image")) {
                    if (submitControl == null) {
                        submitControl = new FormField(name, type, field.attr("value"));
                    }
                    continue;
                }
                formFields.add(new FormField(name, type, field.attr("value")));
            }

            forms.add(new DiscoveredForm(action, method, formFields, submitControl, doc.baseUri()));
        }

        return forms;
    }

    private static String normalizeMethod(String method) {
        return (method.isBlank()) ? "GET" : method.toUpperCase();
    }
}
