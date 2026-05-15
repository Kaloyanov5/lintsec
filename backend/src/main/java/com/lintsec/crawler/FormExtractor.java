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
            String method = normalizeMethod(form.attr("method"));

            Elements fields = form.select("input, textarea, select");
            List<FormField> formFields = new ArrayList<>();
            for (Element field : fields) {
                String name = field.attr("name");
                if (name.isBlank()) {
                    continue;
                }
                String type = field.attr("type");
                if (type.isBlank()) {
                    type = "text";
                }
                if (
                        type.equalsIgnoreCase("submit") ||
                        type.equalsIgnoreCase("button") ||
                        type.equalsIgnoreCase("reset") ||
                        type.equalsIgnoreCase("image")
                ) {
                    continue;
                }
                String value = field.attr("value");

                formFields.add(new FormField(name, type, value));
            }

            forms.add(new DiscoveredForm(action, method, formFields));
        }

        return forms;
    }

    private static String normalizeMethod(String method) {
        return (method.isBlank()) ? "GET" : method.toUpperCase();
    }
}
