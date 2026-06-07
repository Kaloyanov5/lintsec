package com.lintsec.scanner.modules;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MissingSriModuleTest {

    @Test
    void flagsCrossOriginScriptWithoutIntegrity() {
        String html = "<script src=\"https://cdn.other/x.js\"></script>";
        assertEquals(List.of("https://cdn.other/x.js"),
                MissingSriModule.crossOriginResourcesMissingIntegrity("https://site.test/page", html));
    }

    @Test
    void ignoresCrossOriginScriptWithIntegrity() {
        String html = "<script src=\"https://cdn.other/x.js\" integrity=\"sha384-abc\"></script>";
        assertTrue(MissingSriModule.crossOriginResourcesMissingIntegrity("https://site.test/page", html).isEmpty());
    }

    @Test
    void ignoresSameOriginResources() {
        String html = "<script src=\"/local.js\"></script>"
                + "<link rel=\"stylesheet\" href=\"https://site.test/app.css\">";
        assertTrue(MissingSriModule.crossOriginResourcesMissingIntegrity("https://site.test/page", html).isEmpty());
    }

    @Test
    void flagsCrossOriginStylesheetWithoutIntegrity() {
        String html = "<link rel=\"stylesheet\" href=\"https://fonts.other/f.css\">";
        assertEquals(List.of("https://fonts.other/f.css"),
                MissingSriModule.crossOriginResourcesMissingIntegrity("https://site.test/page", html));
    }
}
