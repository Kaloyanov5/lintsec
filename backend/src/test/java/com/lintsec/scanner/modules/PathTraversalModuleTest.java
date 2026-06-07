package com.lintsec.scanner.modules;

import com.lintsec.scanner.PayloadId;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PathTraversalModuleTest {

    @Test
    void detectsUnixPasswdSignature() {
        String body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
        assertEquals(Optional.of(PayloadId.PATH_TRAVERSAL_UNIX), PathTraversalModule.detect(body));
    }

    @Test
    void detectsWindowsWinIniSignature() {
        String body = "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n";
        assertEquals(Optional.of(PayloadId.PATH_TRAVERSAL_WINDOWS), PathTraversalModule.detect(body));
    }

    @Test
    void ignoresOrdinaryHtml() {
        assertEquals(Optional.empty(),
                PathTraversalModule.detect("<html><body>Welcome, root user. Your profile.</body></html>"));
    }

    @Test
    void handlesNullBody() {
        assertEquals(Optional.empty(), PathTraversalModule.detect(null));
    }
}
