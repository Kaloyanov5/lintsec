package com.lintsec.scanner.modules;

import com.lintsec.scanner.PayloadId;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CommandInjectionModuleTest {

    @Test
    void detectsUnixIdOutput() {
        String body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
        assertEquals(Optional.of(PayloadId.CMDI_UNIX_ID), CommandInjectionModule.detect(body));
    }

    @Test
    void detectsWindowsVerOutput() {
        String body = "Microsoft Windows [Version 10.0.19045.3693]";
        assertEquals(Optional.of(PayloadId.CMDI_WINDOWS_VER), CommandInjectionModule.detect(body));
    }

    @Test
    void doesNotMatchGuidLikeText() {
        // "guid=1234" contains "uid=1234" but has no parenthesised group, so must not match.
        assertEquals(Optional.empty(),
                CommandInjectionModule.detect("<p>Your guid=1234 is invalid; gid=5 ignored.</p>"));
    }

    @Test
    void handlesNullBody() {
        assertEquals(Optional.empty(), CommandInjectionModule.detect(null));
    }

    @Test
    void confirmFlagsWhenOutputAppearsOnlyUnderPayload() {
        String idOutput = "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
        assertEquals(Optional.of(PayloadId.CMDI_UNIX_ID),
                CommandInjectionModule.confirmInjection("<html>clean page</html>", idOutput));
    }

    @Test
    void confirmDoesNotFlagWhenOutputAlreadyInBaseline() {
        // A page that legitimately prints `id`-like output (e.g. a sysinfo page) must not be flagged.
        String idOutput = "uid=33(www-data) gid=33(www-data)";
        assertEquals(Optional.empty(),
                CommandInjectionModule.confirmInjection(idOutput, idOutput));
    }

    @Test
    void tightenedRegexRejectsPartialUidGidText() {
        // "uid=1(foo) gid=2" has a parenthesised uid but a bare gid — not real `id` output.
        assertEquals(Optional.empty(),
                CommandInjectionModule.detect("account uid=1(foo) gid=2 disabled"));
    }
}
