package com.lintsec.crawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class FormExtractorTest {

    private static Document parse(String html) {
        // baseUri is what FormExtractor records as the form's pageUrl.
        return Jsoup.parse(html, "https://target.test/page");
    }

    @Test
    void capturesNamedSubmitButtonAsSubmitControlNotAsField() {
        Document doc = parse("""
            <form method="post" action="/save">
              <input type="text" name="q">
              <input type="submit" name="Submit" value="Save">
            </form>
            """);

        List<DiscoveredForm> forms = FormExtractor.extractForms(doc);
        assertEquals(1, forms.size());
        DiscoveredForm form = forms.get(0);

        assertNotNull(form.submitControl());
        assertEquals("Submit", form.submitControl().name());
        assertEquals("Save", form.submitControl().value());

        assertEquals(1, form.fields().size());
        assertEquals("q", form.fields().get(0).name());
    }

    @Test
    void recordsPageUrlFromBaseUri() {
        Document doc = parse("<form action='/x'><input name='a'></form>");
        assertEquals("https://target.test/page", FormExtractor.extractForms(doc).get(0).pageUrl());
    }

    @Test
    void ignoresResetAndUnnamedSubmitButtons() {
        Document doc = parse("""
            <form action="/y">
              <input type="text" name="q">
              <input type="reset" name="clear" value="Clear">
              <input type="submit" value="Go">
            </form>
            """);
        DiscoveredForm form = FormExtractor.extractForms(doc).get(0);
        assertNull(form.submitControl());
        assertEquals(1, form.fields().size());
        assertEquals("q", form.fields().get(0).name());
    }

    @Test
    void capturesImageSubmitControl() {
        Document doc = parse("""
            <form action="/img"><input type="image" name="go" src="b.png"></form>
            """);
        DiscoveredForm form = FormExtractor.extractForms(doc).get(0);
        assertNotNull(form.submitControl());
        assertEquals("go", form.submitControl().name());
        assertEquals("image", form.submitControl().type());
    }

    @Test
    void textareaAndSelectAreFuzzableFields() {
        // textarea/select have no type attribute, so they hit the type-default ("text") path
        // and must still land in fields() (not dropped, not treated as a submit control).
        Document doc = parse("""
            <form method="post" action="/comment">
              <textarea name="body"></textarea>
              <select name="category"><option value="a">A</option></select>
            </form>
            """);
        DiscoveredForm form = FormExtractor.extractForms(doc).get(0);
        assertNull(form.submitControl());
        List<String> names = form.fields().stream().map(FormField::name).sorted().toList();
        assertEquals(List.of("body", "category"), names);
    }
}
