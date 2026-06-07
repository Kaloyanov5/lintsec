package com.lintsec.scanner.modules;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MixedContentModuleTest {

    @Test
    void flagsHttpScriptOnHttpsPage() {
        String html = "<html><head><script src=\"http://cdn.example/x.js\"></script></head></html>";
        assertEquals(List.of("http://cdn.example/x.js"),
                MixedContentModule.activeHttpSubresources("https://site.test/page", html));
    }

    @Test
    void flagsHttpStylesheetAndIframe() {
        String html = "<link rel=\"stylesheet\" href=\"http://cdn.example/s.css\">"
                + "<iframe src=\"http://ads.example/a\"></iframe>";
        assertEquals(List.of("http://cdn.example/s.css", "http://ads.example/a"),
                MixedContentModule.activeHttpSubresources("https://site.test/page", html));
    }

    @Test
    void ignoresHttpsSubresources() {
        String html = "<script src=\"https://cdn.example/x.js\"></script>";
        assertTrue(MixedContentModule.activeHttpSubresources("https://site.test/page", html).isEmpty());
    }

    @Test
    void protocolRelativeResolvesToPageSchemeSoNotFlagged() {
        String html = "<link rel=\"stylesheet\" href=\"//cdn.example/s.css\">";
        assertTrue(MixedContentModule.activeHttpSubresources("https://site.test/page", html).isEmpty());
    }

    @Test
    void skipsNonHttpsPages() {
        String html = "<script src=\"http://cdn.example/x.js\"></script>";
        assertTrue(MixedContentModule.activeHttpSubresources("http://site.test/page", html).isEmpty());
    }
}
